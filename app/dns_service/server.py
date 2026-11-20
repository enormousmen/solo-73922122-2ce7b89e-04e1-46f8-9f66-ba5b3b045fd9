"""本地演示 DNS 服务（UDP/53 + 控制面 HTTP/8053）。

解析数据按“场景 profile”组织，可通过 HTTP 控制面随时热切换，
用于演示“检查后换址”（DNS rebinding 类场景）：
  * profile=allowed 时域名解析到允许网段的目标；
  * 切换到 swapped 后同名域名解析到禁止网段，探测必须在连接前拦截；
  * profile=mixed 时一次应答同时包含允许与禁止地址，整体拒绝。

除内置场景外，控制面还支持“自定义场景”整组发布（POST /profiles/publish）：
  * 只接受 demo.test 下的具体子域名（不接受裸域、通配符或其他后缀）；
  * A 记录地址必须全部落在 172.31.10.0/24；
  * 请求携带当前修订号（revision），过期修订号返回 409 冲突；
  * 发布成功后整组替换自定义记录并唯一启用 custom 场景；
  * 发布与场景切换每次成功都把同一个修订号 +1；
  * 校验/保存失败不改动任何内存状态与落盘状态，UDP 继续按原场景应答；
  * 最后一次成功保存的自定义记录、启用场景与修订号持久化，重启后恢复。

只实现 A 记录；未知域名返回 NXDOMAIN；非 A 查询返回 SERVFAIL。
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import re
from pathlib import Path

from ..probe import dns_wire

PROFILES_DIR = Path(os.getenv("DNS_PROFILES_DIR", "/app/dns-profiles"))
STATE_FILE = Path(os.getenv("DNS_STATE_FILE", "/tmp/dns-state/state.json"))
CONTROL_PORT = int(os.getenv("DNS_CONTROL_PORT", "8053"))
UDP_PORT = int(os.getenv("DNS_UDP_PORT", "53"))

CUSTOM_PROFILE = "custom"
CUSTOM_SUFFIX = ".demo.test"
ALLOWED_NETWORK = ipaddress.ip_network("172.31.10.0/24")
INITIAL_REVISION = 1

_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


class PublishValidationError(ValueError):
    """发布内容校验失败（结构、域名或地址不合法）。"""


class RevisionConflictError(Exception):
    """请求携带的修订号与服务端当前修订号不一致（已过期）。"""


def validate_qname(name: object) -> str:
    """校验并规范化自定义记录的域名。

    只接受 demo.test 下的具体子域名：至少一个非空标签，不接受裸
    demo.test、通配符、空标签或其他后缀。返回小写、无尾点的规范形式。
    """
    if not isinstance(name, str) or not name.strip():
        raise PublishValidationError("域名必须是非空字符串")
    normalized = name.strip().lower().rstrip(".")
    if not normalized.endswith(CUSTOM_SUFFIX):
        raise PublishValidationError(
            f"域名 {name!r} 不在 {CUSTOM_SUFFIX.lstrip('.')} 下，仅接受该后缀的子域名"
        )
    left = normalized[: -len(CUSTOM_SUFFIX)]
    if not left or left.startswith("."):
        raise PublishValidationError(
            f"域名 {name!r} 不是 {CUSTOM_SUFFIX.lstrip('.')} 下的具体子域名"
        )
    labels = left.split(".")
    if any(not _LABEL_RE.match(label) for label in labels) or "*" in normalized:
        raise PublishValidationError(
            f"域名 {name!r} 含非法标签（仅允许字母数字与连字符，不接受通配符）"
        )
    if len(normalized) > 253:
        raise PublishValidationError(f"域名 {name!r} 超出 253 字符长度限制")
    return normalized


def validate_records(records: object) -> dict[str, list[str]]:
    """校验整组 A 记录，全部合法后才返回规范化的新记录。

    任一记录非法即抛 PublishValidationError，调用方保证不会部分生效。
    """
    if not isinstance(records, dict) or not records:
        raise PublishValidationError(
            "records 必须是非空对象，格式为 {\"子域名.demo.test\": [\"IPv4\", ...]}"
        )
    zones: dict[str, list[str]] = {}
    for raw_name, raw_ips in records.items():
        name = validate_qname(raw_name)
        if not isinstance(raw_ips, list) or not raw_ips:
            raise PublishValidationError(
                f"域名 {name} 的 A 记录必须是非空数组"
            )
        ips: list[str] = []
        for raw_ip in raw_ips:
            if not isinstance(raw_ip, str):
                raise PublishValidationError(f"域名 {name} 的地址必须是字符串")
            try:
                ip = ipaddress.ip_address(raw_ip.strip())
            except ValueError as exc:
                raise PublishValidationError(
                    f"域名 {name} 的地址 {raw_ip!r} 不是合法 IP"
                ) from exc
            if not isinstance(ip, ipaddress.IPv4Address):
                raise PublishValidationError(
                    f"仅接受 IPv4 A 记录，域名 {name} 的 {raw_ip!r} 不是 IPv4"
                )
            if ip not in ALLOWED_NETWORK:
                raise PublishValidationError(
                    f"域名 {name} 的地址 {raw_ip} 不在允许网段 {ALLOWED_NETWORK} 内"
                )
            text = str(ip)
            if text not in ips:  # 去重但保持提交顺序
                ips.append(text)
        zones[name] = ips
    return zones


class ProfileStore:
    def __init__(
        self,
        profiles_dir: Path | None = None,
        state_file: Path | None = None,
    ) -> None:
        self._profiles_dir = profiles_dir or PROFILES_DIR
        self._state_file = state_file or STATE_FILE
        self._profiles: dict[str, dict[str, list[str]]] = {}
        self._custom: dict[str, list[str]] = {}
        self._active = ""
        self._revision = INITIAL_REVISION
        self._lock = asyncio.Lock()
        self._load_builtin_profiles()
        self._load_state()

    # ------------------------------------------------------------ 加载/持久化
    def _load_builtin_profiles(self) -> None:
        for path in sorted(self._profiles_dir.glob("*.json")):
            data = json.loads(path.read_text())
            name = data["profile"]
            zones = {k.lower(): list(v) for k, v in data["zones"].items()}
            self._profiles[name] = zones

    def _load_state(self) -> None:
        """恢复最后一次成功保存的状态；兼容旧版纯文本状态文件。"""
        self._state_file.parent.mkdir(parents=True, exist_ok=True)
        migrated = False
        if self._state_file.exists():
            raw = self._state_file.read_text().strip()
            data = None
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, dict):
                    data = parsed
            except json.JSONDecodeError:
                # 旧版本状态文件只保存场景名（纯文本），做一次性迁移
                if raw and raw in self._profiles:
                    data = {"revision": INITIAL_REVISION, "active": raw, "custom": {}}
                    migrated = True
            if data is not None:
                self._restore_dict(data)
        if self._active not in self._available_profile_names():
            self._active = next(iter(self._profiles))
            migrated = True
        if migrated or not self._state_file.exists():
            self._persist_locked()

    def _restore_dict(self, data: dict) -> None:
        revision = data.get("revision")
        if isinstance(revision, int) and not isinstance(revision, bool) and revision >= 1:
            self._revision = revision
        custom = data.get("custom")
        if isinstance(custom, dict):
            try:
                self._custom = validate_records(custom)
            except PublishValidationError:
                # 落盘数据损坏时丢弃自定义记录，但保留修订号与内置场景
                self._custom = {}
        active = data.get("active")
        if isinstance(active, str):
            self._active = active

    def _available_profile_names(self) -> set[str]:
        names = set(self._profiles)
        if self._custom:
            names.add(CUSTOM_PROFILE)
        return names

    def _persist_locked(
        self,
        revision: int | None = None,
        active: str | None = None,
        custom: dict[str, list[str]] | None = None,
    ) -> None:
        """原子写入完整状态（修订号、启用场景、自定义记录）。

        参数为 None 时取当前实例值；提交变更时显式传入新值，保证先落盘
        成功后才修改内存状态，保存失败不会污染运行中的场景与修订号。
        """
        payload = {
            "revision": self._revision if revision is None else revision,
            "active": self._active if active is None else active,
            "custom": self._custom if custom is None else custom,
        }
        tmp = self._state_file.with_name(self._state_file.name + ".tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2))
        os.replace(tmp, self._state_file)

    # ------------------------------------------------------------------ 查询
    @property
    def active(self) -> str:
        return self._active

    @property
    def revision(self) -> int:
        return self._revision

    def list_profiles(self) -> dict[str, dict[str, list[str]]]:
        profiles = {name: dict(zones) for name, zones in self._profiles.items()}
        if self._custom:  # 自定义记录为空时不暴露空壳场景
            profiles[CUSTOM_PROFILE] = dict(self._custom)
        return profiles

    def snapshot(self) -> dict:
        return {
            "revision": self._revision,
            "active": self._active,
            "profiles": self.list_profiles(),
        }

    def lookup(self, qname: str) -> tuple[int, list[str]]:
        qname = qname.lower().rstrip(".")
        if self._active == CUSTOM_PROFILE:
            zones = self._custom
        else:
            zones = self._profiles[self._active]
        if qname in zones:
            return dns_wire.RCODE_OK, zones[qname]
        # 支持通配后缀（如 *.demo.test，仅内置场景可能包含）
        for suffix, ips in zones.items():
            if suffix.startswith("*.") and qname.endswith(suffix[1:]):
                return dns_wire.RCODE_OK, ips
        return dns_wire.RCODE_NAME_ERROR, []

    # ------------------------------------------------------------------ 变更
    async def switch(
        self, name: str, expected_revision: int | None = None
    ) -> bool:
        """切换启用场景；成功即推进修订号并落盘。

        expected_revision 为 None 时不做乐观锁校验（兼容旧调用方）；
        传入时与当前修订号不一致抛 RevisionConflictError。
        """
        async with self._lock:
            if name not in self._available_profile_names():
                return False
            if (
                expected_revision is not None
                and expected_revision != self._revision
            ):
                raise RevisionConflictError(
                    f"修订号 {expected_revision} 已过期，当前修订号为 {self._revision}"
                )
            # 先落盘再改内存：保存失败时内存与 UDP 应答完全不受影响
            self._persist_locked(revision=self._revision + 1, active=name)
            self._active = name
            self._revision += 1
            return True

    async def publish(
        self, expected_revision: object, records: object
    ) -> dict[str, list[str]]:
        """整组替换自定义 A 记录并启用唯一自定义场景。

        先校验修订号，再校验整组记录；任何一步失败都不改动现有状态，
        全部通过后才一次性替换、切换、推进修订号并落盘。
        """
        async with self._lock:
            if not isinstance(expected_revision, int) or isinstance(
                expected_revision, bool
            ):
                raise PublishValidationError("revision 必须是整数修订号")
            if expected_revision != self._revision:
                raise RevisionConflictError(
                    f"修订号 {expected_revision} 已过期，当前修订号为 {self._revision}"
                )
            zones = validate_records(records)
            # 先落盘再改内存：保存失败时保留原场景、原修订与原自定义记录，
            # UDP 继续按原场景应答
            self._persist_locked(
                revision=self._revision + 1,
                active=CUSTOM_PROFILE,
                custom=zones,
            )
            self._custom = zones
            self._active = CUSTOM_PROFILE
            self._revision += 1
            return dict(zones)


class DnsUdpServer(asyncio.DatagramProtocol):
    def __init__(self, store: ProfileStore) -> None:
        self._store = store
        self._transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:  # type: ignore[override]
        self._transport = transport

    def connection_lost(self, exc) -> None:  # noqa: ANN001
        self._transport = None

    def datagram_received(self, data: bytes, addr) -> None:  # noqa: ANN001
        try:
            msg = dns_wire.parse_message(data, require_qr=False)
            question = msg.questions[0] if msg.questions else None
            if question is None or question.qtype != dns_wire.TYPE_A:
                reply = dns_wire.build_response(
                    msg.qid, question, rcode=dns_wire.RCODE_SERVFAIL
                )
            else:
                rcode, ips = self._store.lookup(question.qname)
                reply = dns_wire.build_response(
                    msg.qid, question, rcode=rcode, answers=ips
                )
        except (dns_wire.DnsProtocolError, IndexError):
            reply = b""
        if reply and self._transport is not None:
            self._transport.sendto(reply, addr)


def build_control_app(store: ProfileStore):
    from aiohttp import web  # 延迟导入，仅 DNS 服务需要

    async def get_profiles(_request):
        return web.json_response(store.snapshot())

    async def publish(request):
        try:
            body = await request.json()
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
            return web.json_response({"error": "请求体必须是合法 JSON"}, status=400)
        if not isinstance(body, dict):
            return web.json_response({"error": "请求体必须是 JSON 对象"}, status=400)
        try:
            await store.publish(body.get("revision"), body.get("records"))
        except RevisionConflictError as exc:
            return web.json_response(
                {
                    "error": str(exc),
                    "current_revision": store.revision,
                    "active": store.active,
                },
                status=409,
            )
        except PublishValidationError as exc:
            return web.json_response({"error": str(exc)}, status=400)
        return web.json_response(store.snapshot())

    async def switch(request):
        try:
            body = await request.json()
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
            return web.json_response({"error": "请求体必须是合法 JSON"}, status=400)
        if not isinstance(body, dict):
            return web.json_response({"error": "请求体必须是 JSON 对象"}, status=400)
        name = str(body.get("profile", ""))
        revision = body.get("revision")
        if revision is not None and (
            not isinstance(revision, int) or isinstance(revision, bool)
        ):
            return web.json_response(
                {"error": "revision 必须是整数修订号"}, status=400
            )
        try:
            switched = await store.switch(name, revision)
        except RevisionConflictError as exc:
            return web.json_response(
                {
                    "error": str(exc),
                    "current_revision": store.revision,
                    "active": store.active,
                },
                status=409,
            )
        if not switched:
            return web.json_response(
                {
                    "error": f"未知 profile: {name!r}",
                    "available": list(store.list_profiles()),
                },
                status=404,
            )
        return web.json_response(store.snapshot())

    app = web.Application()
    app.router.add_get("/profiles", get_profiles)
    app.router.add_post("/profiles/publish", publish)
    app.router.add_post("/profiles/switch", switch)
    return app


async def _control_app(store: ProfileStore) -> "asyncio.base_events.Server":
    from aiohttp import web

    app = build_control_app(store)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", CONTROL_PORT)
    await site.start()
    return site


async def serve() -> None:
    store = ProfileStore()
    loop = asyncio.get_running_loop()
    transport, _protocol = await loop.create_datagram_endpoint(
        lambda: DnsUdpServer(store),
        local_addr=("0.0.0.0", UDP_PORT),
    )
    await _control_app(store)
    print(
        f"[dns-service] UDP/{UDP_PORT} 已启动，初始 profile={store.active!r}，"
        f"revision={store.revision}，控制面 HTTP/{CONTROL_PORT}",
        flush=True,
    )
    try:
        await asyncio.Event().wait()
    finally:
        transport.close()


if __name__ == "__main__":
    asyncio.run(serve())
