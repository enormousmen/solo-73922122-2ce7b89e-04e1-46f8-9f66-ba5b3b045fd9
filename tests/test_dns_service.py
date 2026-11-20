"""本地 DNS 服务测试：修订号、自定义场景发布、冲突与持久化恢复。

覆盖需求关键点：
* GET /profiles 返回当前修订号；
* POST /profiles/publish 整组替换并唯一启用 custom 场景；
* 仅接受 demo.test 下具体子域名，地址必须在 172.31.10.0/24 内；
* 发布与切换每次成功都推进同一个修订号，过期修订号返回 409；
* 校验/保存失败时控制面与 UDP 均保持原场景、原修订；
* 发布成功后控制面显示新场景/修订，UDP 按新记录应答；
* 重启恢复最后一次成功保存的自定义记录、场景与修订号；
* 内置场景仍可热切换。
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest
from aiohttp.test_utils import TestClient, TestServer

from app.dns_service.server import (
    CUSTOM_PROFILE,
    DnsUdpServer,
    ProfileStore,
    build_control_app,
)
from app.probe import dns_wire
from app.probe.dns_client import DnsError, DnsResolver

PROFILES_DIR = Path(__file__).resolve().parent.parent / "dns-profiles"


@pytest.fixture()
def state_file(tmp_path):
    return tmp_path / "state" / "state.json"


@pytest.fixture()
def store(state_file):
    return ProfileStore(profiles_dir=PROFILES_DIR, state_file=state_file)


@pytest.fixture()
async def client(store):
    server = TestServer(build_control_app(store))
    async with TestClient(server) as c:
        yield c


@pytest.fixture()
async def udp_resolver(store):
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: DnsUdpServer(store), local_addr=("127.0.0.1", 0)
    )
    port = transport.get_extra_info("socket").getsockname()[1]
    resolver = DnsResolver("127.0.0.1", port=port, timeout=2.0, retries=0)
    try:
        yield resolver
    finally:
        transport.close()


async def resolve(resolver: DnsResolver, name: str) -> list[str]:
    return await resolver.resolve_a(name)


# ----------------------------------------------------------------- 初始状态
class TestInitialState:
    async def test_profiles_include_revision_and_builtins(self, client, store):
        r = await client.get("/profiles")
        assert r.status == 200
        body = await r.json()
        assert body["revision"] == 1
        assert body["active"] in {"allowed", "swapped", "mixed", "loop"}
        # 初始没有自定义记录时不暴露空壳 custom
        assert CUSTOM_PROFILE not in body["profiles"]
        assert set(body["profiles"]) == {"allowed", "swapped", "mixed", "loop"}
        assert store.revision == 1


# ----------------------------------------------------------------- 发布成功
class TestPublishSuccess:
    async def test_publish_replaces_and_activates_custom(self, client, store):
        records = {
            "webhook-a.demo.test": ["172.31.10.21"],
            "webhook-b.demo.test": ["172.31.10.22", "172.31.10.23"],
        }
        r = await client.post(
            "/profiles/publish", json={"revision": 1, "records": records}
        )
        assert r.status == 200
        body = await r.json()
        assert body["revision"] == 2
        assert body["active"] == CUSTOM_PROFILE
        assert body["profiles"][CUSTOM_PROFILE] == records
        # 内置场景仍然存在
        assert "allowed" in body["profiles"]

    async def test_publish_normalizes_names_and_dedupes_ips(self, client, store):
        r = await client.post(
            "/profiles/publish",
            json={
                "revision": 1,
                "records": {
                    "UPPER.Label.demo.test.": ["172.31.10.5", "172.31.10.5"],
                },
            },
        )
        assert r.status == 200
        body = await r.json()
        assert body["profiles"][CUSTOM_PROFILE] == {
            "upper.label.demo.test": ["172.31.10.5"]
        }

    async def test_publish_is_full_replacement(self, client, store):
        await client.post(
            "/profiles/publish",
            json={
                "revision": 1,
                "records": {"old.demo.test": ["172.31.10.10"]},
            },
        )
        r = await client.post(
            "/profiles/publish",
            json={
                "revision": 2,
                "records": {"new.demo.test": ["172.31.10.11"]},
            },
        )
        body = await r.json()
        assert body["revision"] == 3
        custom = body["profiles"][CUSTOM_PROFILE]
        assert custom == {"new.demo.test": ["172.31.10.11"]}
        assert "old.demo.test" not in custom

    async def test_udp_answers_new_records_after_publish(
        self, client, store, udp_resolver
    ):
        await client.post(
            "/profiles/publish",
            json={
                "revision": 1,
                "records": {"webhook.demo.test": ["172.31.10.30"]},
            },
        )
        ips = await resolve(udp_resolver, "webhook.demo.test")
        assert ips == ["172.31.10.30"]

    async def test_udp_nxdomain_for_names_dropped_by_replacement(
        self, client, store, udp_resolver
    ):
        await client.post(
            "/profiles/publish",
            json={
                "revision": 1,
                "records": {"keep.demo.test": ["172.31.10.30"]},
            },
        )
        await client.post(
            "/profiles/publish",
            json={
                "revision": 2,
                "records": {"only.demo.test": ["172.31.10.31"]},
            },
        )
        # 函数内导入：其他测试模块会 reload dns_client，模块级类引用可能过期
        from app.probe.dns_client import DnsError

        with pytest.raises(DnsError, match="NXDOMAIN"):
            await resolve(udp_resolver, "keep.demo.test")
        assert await resolve(udp_resolver, "only.demo.test") == ["172.31.10.31"]


# ----------------------------------------------------------------- 校验失败
class TestPublishValidation:
    @pytest.mark.parametrize(
        "name",
        [
            "demo.test",            # 裸域，不是具体子域名
            "*.demo.test",          # 通配符
            "demo.test.evil.com",   # 后缀伪造
            "evil.example",         # 其他后缀
            ".demo.test",           # 空标签
            "bad name.demo.test",   # 非法字符
            "exa" + "m" * 250 + ".demo.test",  # 超长
        ],
    )
    async def test_rejects_invalid_names(self, client, store, name):
        before = store.snapshot()
        r = await client.post(
            "/profiles/publish",
            json={"revision": 1, "records": {name: ["172.31.10.10"]}},
        )
        assert r.status == 400
        body = await r.json()
        assert "error" in body
        # 失败后控制面仍显示原场景与修订
        assert store.snapshot() == before
        assert store.revision == 1

    @pytest.mark.parametrize(
        "ip",
        [
            "172.31.20.10",   # 禁止网段
            "172.31.9.255",   # 相邻网段
            "172.31.11.1",
            "8.8.8.8",
            "172.31.10.300",  # 非法地址
            "not-an-ip",
        ],
    )
    async def test_rejects_ips_outside_allowed_network(self, client, store, ip):
        before = store.snapshot()
        r = await client.post(
            "/profiles/publish",
            json={"revision": 1, "records": {"a.demo.test": [ip]}},
        )
        assert r.status == 400
        assert store.snapshot() == before

    async def test_rejects_ipv6(self, client, store):
        r = await client.post(
            "/profiles/publish",
            json={"revision": 1, "records": {"a.demo.test": ["2001:db8::1"]}},
        )
        assert r.status == 400
        assert store.revision == 1

    async def test_rejects_empty_records(self, client, store):
        for payload in ({}, {"a.demo.test": []}):
            r = await client.post(
                "/profiles/publish", json={"revision": 1, "records": payload}
            )
            assert r.status == 400
        assert store.revision == 1

    async def test_rejects_non_integer_revision(self, client, store):
        r = await client.post(
            "/profiles/publish",
            json={
                "revision": "1",
                "records": {"a.demo.test": ["172.31.10.10"]},
            },
        )
        assert r.status == 400
        # bool 是 int 子类，也必须拒绝
        r2 = await client.post(
            "/profiles/publish",
            json={
                "revision": True,
                "records": {"a.demo.test": ["172.31.10.10"]},
            },
        )
        assert r2.status == 400
        assert store.revision == 1

    async def test_rejects_malformed_json(self, client, store):
        r = await client.post(
            "/profiles/publish", data="{not-json", headers={"Content-Type": "application/json"}
        )
        assert r.status == 400
        assert store.revision == 1

    async def test_failed_publish_keeps_udp_on_old_answers(
        self, client, store, udp_resolver
    ):
        # 先成功发布一组记录
        await client.post(
            "/profiles/publish",
            json={
                "revision": 1,
                "records": {"good.demo.test": ["172.31.10.40"]},
            },
        )
        # 再提交非法记录（地址越界），必须失败且不影响 UDP
        r = await client.post(
            "/profiles/publish",
            json={
                "revision": 2,
                "records": {"bad.demo.test": ["172.31.20.40"]},
            },
        )
        assert r.status == 400
        assert store.active == CUSTOM_PROFILE
        assert store.revision == 2
        assert await resolve(udp_resolver, "good.demo.test") == ["172.31.10.40"]


# ----------------------------------------------------------------- 修订冲突
class TestRevisionConflict:
    async def test_stale_revision_returns_409_without_change(self, client, store):
        await client.post(
            "/profiles/publish",
            json={
                "revision": 1,
                "records": {"a.demo.test": ["172.31.10.10"]},
            },
        )
        before = store.snapshot()
        r = await client.post(
            "/profiles/publish",
            json={
                "revision": 1,  # 已过期，当前为 2
                "records": {"b.demo.test": ["172.31.10.11"]},
            },
        )
        assert r.status == 409
        body = await r.json()
        assert body["current_revision"] == 2
        assert store.snapshot() == before

    async def test_switch_advances_shared_revision(self, client, store):
        r = await client.post(
            "/profiles/switch", json={"profile": "swapped"}
        )
        assert r.status == 200
        body = await r.json()
        assert body["active"] == "swapped"
        assert body["revision"] == 2

        r2 = await client.post("/profiles/switch", json={"profile": "allowed"})
        body2 = await r2.json()
        assert body2["revision"] == 3
        assert body2["active"] == "allowed"

    async def test_switch_with_stale_revision_conflicts(self, client, store):
        await client.post("/profiles/switch", json={"profile": "swapped"})
        r = await client.post(
            "/profiles/switch", json={"profile": "allowed", "revision": 1}
        )
        assert r.status == 409
        assert store.active == "swapped"
        assert store.revision == 2

    async def test_switch_with_current_revision_succeeds(self, client, store):
        await client.post("/profiles/switch", json={"profile": "swapped"})
        r = await client.post(
            "/profiles/switch", json={"profile": "allowed", "revision": 2}
        )
        assert r.status == 200
        body = await r.json()
        assert body["active"] == "allowed"
        assert body["revision"] == 3

    async def test_switch_unknown_profile_404(self, client, store):
        before = store.snapshot()
        r = await client.post("/profiles/switch", json={"profile": "nope"})
        assert r.status == 404
        assert store.snapshot() == before

    async def test_publish_after_switch_uses_latest_revision(self, client, store):
        await client.post("/profiles/switch", json={"profile": "swapped"})  # rev 2
        r = await client.post(
            "/profiles/publish",
            json={
                "revision": 2,
                "records": {"a.demo.test": ["172.31.10.10"]},
            },
        )
        assert r.status == 200
        body = await r.json()
        assert body["revision"] == 3
        assert body["active"] == CUSTOM_PROFILE

    async def test_failed_switch_does_not_advance_revision(self, client, store):
        r = await client.post("/profiles/switch", json={"profile": "missing"})
        assert r.status == 404
        assert store.revision == 1


# ----------------------------------------------------------------- 场景切换
class TestSwitching:
    async def test_builtin_still_switchable_after_publish(
        self, client, store, udp_resolver
    ):
        await client.post(
            "/profiles/publish",
            json={
                "revision": 1,
                "records": {"swapped.demo.test": ["172.31.10.99"]},
            },
        )
        assert await resolve(udp_resolver, "swapped.demo.test") == ["172.31.10.99"]

        r = await client.post("/profiles/switch", json={"profile": "swapped"})
        assert r.status == 200
        # 内置 swapped 场景里 swapped.demo.test 解析到禁止网段地址
        assert await resolve(udp_resolver, "swapped.demo.test") == ["172.31.20.10"]

        # 切回自定义场景，自定义记录仍然保留
        r2 = await client.post(
            "/profiles/switch", json={"profile": CUSTOM_PROFILE, "revision": store.revision}
        )
        assert r2.status == 200
        assert await resolve(udp_resolver, "swapped.demo.test") == ["172.31.10.99"]

    async def test_udp_nxdomain_unknown_name_in_custom(
        self, client, store, udp_resolver
    ):
        await client.post(
            "/profiles/publish",
            json={
                "revision": 1,
                "records": {"known.demo.test": ["172.31.10.10"]},
            },
        )
        # 函数内导入：其他测试模块会 reload dns_client，模块级类引用可能过期
        from app.probe.dns_client import DnsError

        with pytest.raises(DnsError, match="NXDOMAIN"):
            await resolve(udp_resolver, "unknown.demo.test")


# ----------------------------------------------------------------- 持久化
class TestPersistence:
    async def test_restart_restores_custom_records_active_and_revision(
        self, client, state_file
    ):
        records = {"persist.demo.test": ["172.31.10.61", "172.31.10.62"]}
        await client.post(
            "/profiles/publish", json={"revision": 1, "records": records}
        )
        # 再切换到内置场景，验证恢复的是“当时启用的场景”
        await client.post("/profiles/switch", json={"profile": "allowed"})

        revived = ProfileStore(profiles_dir=PROFILES_DIR, state_file=state_file)
        assert revived.revision == 3
        assert revived.active == "allowed"
        assert revived.list_profiles()[CUSTOM_PROFILE] == records

    async def test_restart_restores_custom_active_profile(
        self, client, store, state_file, udp_resolver
    ):
        records = {"after-restart.demo.test": ["172.31.10.77"]}
        await client.post(
            "/profiles/publish", json={"revision": 1, "records": records}
        )
        revived = ProfileStore(profiles_dir=PROFILES_DIR, state_file=state_file)
        assert revived.active == CUSTOM_PROFILE
        assert revived.revision == 2
        assert revived.lookup("after-restart.demo.test") == (
            dns_wire.RCODE_OK,
            ["172.31.10.77"],
        )

    async def test_failed_publish_does_not_overwrite_saved_state(
        self, client, state_file
    ):
        records = {"saved.demo.test": ["172.31.10.88"]}
        await client.post(
            "/profiles/publish", json={"revision": 1, "records": records}
        )
        # 校验失败的发布
        bad = await client.post(
            "/profiles/publish",
            json={"revision": 2, "records": {"x.demo.test": ["172.31.20.1"]}},
        )
        assert bad.status == 400
        # 冲突失败的发布
        conflict = await client.post(
            "/profiles/publish",
            json={"revision": 99, "records": {"y.demo.test": ["172.31.10.2"]}},
        )
        assert conflict.status == 409

        on_disk = json.loads(state_file.read_text())
        assert on_disk["revision"] == 2
        assert on_disk["active"] == CUSTOM_PROFILE
        assert on_disk["custom"] == records

        revived = ProfileStore(profiles_dir=PROFILES_DIR, state_file=state_file)
        assert revived.revision == 2
        assert revived.list_profiles()[CUSTOM_PROFILE] == records

    async def test_legacy_plaintext_state_file_migrates(self, state_file):
        state_file.parent.mkdir(parents=True, exist_ok=True)
        state_file.write_text("swapped")
        revived = ProfileStore(profiles_dir=PROFILES_DIR, state_file=state_file)
        assert revived.active == "swapped"
        assert revived.revision == 1
        # 迁移后状态文件升级为 JSON 格式
        saved = json.loads(state_file.read_text())
        assert saved["active"] == "swapped"
        assert saved["revision"] == 1
        assert saved["custom"] == {}

    async def test_corrupt_state_falls_back_to_builtin(self, state_file):
        state_file.parent.mkdir(parents=True, exist_ok=True)
        state_file.write_text("{broken-json")
        revived = ProfileStore(profiles_dir=PROFILES_DIR, state_file=state_file)
        assert revived.active in {"allowed", "swapped", "mixed", "loop"}
        assert revived.revision == 1

    async def test_unknown_active_in_state_falls_back_to_builtin(self, state_file):
        state_file.parent.mkdir(parents=True, exist_ok=True)
        state_file.write_text(json.dumps({
            "revision": 7,
            "active": "ghost",
            "custom": {"a.demo.test": ["172.31.10.10"]},
        }))
        revived = ProfileStore(profiles_dir=PROFILES_DIR, state_file=state_file)
        assert revived.active in {"allowed", "swapped", "mixed", "loop"}
        assert revived.revision == 7
        # 自定义记录仍保留，可重新切回 custom
        assert revived.list_profiles()[CUSTOM_PROFILE] == {
            "a.demo.test": ["172.31.10.10"]
        }

    async def test_persist_failure_keeps_memory_and_disk_state(
        self, client, store, state_file
    ):
        # 先成功发布一次，制造已落盘的基线状态
        ok = await client.post(
            "/profiles/publish",
            json={
                "revision": 1,
                "records": {"baseline.demo.test": ["172.31.10.9"]},
            },
        )
        assert ok.status == 200
        disk_before = state_file.read_text()
        mem_before = store.snapshot()

        # 模拟落盘失败：原子替换抛 OSError
        original_persist = store._persist_locked

        def failing_persist(*args, **kwargs):
            raise OSError("模拟磁盘故障")

        store._persist_locked = failing_persist
        with pytest.raises(OSError):
            await store.publish(
                store.revision, {"boom.demo.test": ["172.31.10.10"]}
            )
        # 内存中的场景、修订号、自定义记录均未被部分修改
        assert store.snapshot() == mem_before
        assert store.revision == 2
        assert store.active == CUSTOM_PROFILE
        store._persist_locked = original_persist

        # 磁盘上仍是基线状态（重启恢复也不受失败事务影响）
        assert state_file.read_text() == disk_before
        revived = ProfileStore(profiles_dir=PROFILES_DIR, state_file=state_file)
        assert revived.snapshot()["profiles"][CUSTOM_PROFILE] == mem_before[
            "profiles"
        ][CUSTOM_PROFILE]

        # 故障恢复后服务仍可正常发布（状态机未被污染）
        r = await client.post(
            "/profiles/publish",
            json={
                "revision": 2,
                "records": {"recovered.demo.test": ["172.31.10.12"]},
            },
        )
        assert r.status == 200
        body = await r.json()
        assert body["revision"] == 3
        assert body["active"] == CUSTOM_PROFILE
