#!/usr/bin/env bash
# 本地 DNS 自定义场景发布与应答核验脚本。
#
# 前置：docker compose up -d --build 已就绪。
#   控制 API 仅发布在宿主机回环：http://127.0.0.1:8053
#   UDP 解析器仅发布在宿主机回环：127.0.0.1:5353
#
# 用法：./scripts/dns-verify.sh
# 可用环境变量覆盖：DNS_CTRL=http://127.0.0.1:8053 DNS_UDP=127.0.0.1:5353
set -euo pipefail

CTRL="${DNS_CTRL:-http://127.0.0.1:8053}"
UDP_HOST="${DNS_UDP%:*}"
UDP_PORT="${DNS_UDP##*:}"
UDP_HOST="${UDP_HOST:-127.0.0.1}"
UDP_PORT="${UDP_PORT:-5353}"

# 纯标准库 DNS A 查询：dns_query <name>，打印应答地址（每行一个），
# NXDOMAIN/失败时以非零状态退出。不依赖 dig/nslookup。
dns_query() {
  python3 - "$UDP_HOST" "$UDP_PORT" "$1" <<'PY'
import socket, struct, sys

server, port, qname = sys.argv[1], int(sys.argv[2]), sys.argv[3].rstrip(".")
qid = 0x1357
labels = qname.split(".")
question = b"".join(bytes([len(l)]) + l.encode() for l in labels) + b"\x00"
# 头部：标准查询、RD=1；尾部 QTYPE=A(1) QCLASS=IN(1)
packet = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + question + struct.pack("!HH", 1, 1)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(3)
sock.sendto(packet, (server, port))
data = sock.recv(4096)
rcode = data[3] & 0x0F
if rcode != 0:
    print(f"rcode={rcode}", file=sys.stderr)
    sys.exit(2)
ancount = struct.unpack("!H", data[6:8])[0]
off = 12
# 跳过 question 段
while data[off] != 0:
    off += data[off] + 1
off += 5
answers = []
for _ in range(ancount):
    # 应答名可能是压缩指针（2 字节）或普通名
    if data[off] & 0xC0 == 0xC0:
        off += 2
    else:
        while data[off] != 0:
            off += data[off] + 1
        off += 1
    rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", data[off:off + 10])
    off += 10
    rdata = data[off:off + rdlen]
    off += rdlen
    if rtype == 1 and rdlen == 4:
        answers.append(socket.inet_ntoa(rdata))
if not answers:
    sys.exit(3)
print("\n".join(answers))
PY
}

api() {  # api <method> <path> [json-body]
  if [ "$#" -eq 3 ]; then
    curl -sS -w '\n%{http_code}' -X "$1" "$CTRL$2" \
      -H 'Content-Type: application/json' -d "$3"
  else
    curl -sS -w '\n%{http_code}' -X "$1" "$CTRL$2"
  fi
}

show() {  # 拆出最后一行 HTTP 状态码，其余为响应体（JSON 经 jq 解码中文）
  local out code body
  out="$(cat)"
  code="${out##*$'\n'}"
  body="${out%$'\n'*}"
  echo "HTTP $code  $(echo "$body" | jq -c . 2>/dev/null || echo "$body")"
  echo "$code"
}

echo "### 1. 读取当前修订号"
REV="$(curl -sS "$CTRL/profiles" | jq .revision)"
echo "当前 revision=$REV"

echo
echo "### 2. 发布整组自定义 A 记录（仅 demo.test 子域名、172.31.10.0/24）"
PUBLISH="$(jq -n --argjson rev "$REV" '{revision:$rev, records:{
  "webhook-a.demo.test": ["172.31.10.21"],
  "webhook-b.demo.test": ["172.31.10.22", "172.31.10.23"]
}}')"
RESULT="$(api POST /profiles/publish "$PUBLISH")"
CODE="$(printf '%s' "$RESULT" | tail -1)"
echo "HTTP $CODE  $(printf '%s' "$RESULT" | head -n -1 \
  | jq -c '{revision, active, custom: .profiles.custom}' 2>/dev/null || true)"
[ "$CODE" = "200" ] || { echo "发布失败"; exit 1; }
REV=$((REV + 1))
echo
echo "### 3. 用过期修订号再发布一次（预期 409 冲突，场景不变）"
STALE="$(jq -n --argjson rev "$((REV - 1))" '{revision:$rev, records:{
  "stale.demo.test": ["172.31.10.99"]
}}')"
api POST /profiles/publish "$STALE" | show

echo
echo "### 4. 非法内容被拒（预期 400，修订号不推进）"
BAD="$(jq -n --argjson rev "$REV" '{revision:$rev, records:{
  "evil.example": ["172.31.20.10"]
}}')"
api POST /profiles/publish "$BAD" | show

echo
echo "### 5. UDP 核验：查询刚发布的记录（经 $UDP_HOST:$UDP_PORT）"
for name in webhook-a.demo.test webhook-b.demo.test; do
  echo "A $name ->"
  dns_query "$name" | sed 's/^/    /'
done

echo
echo "### 6. 切回内置场景 allowed，再切回 custom（每次成功修订号 +1）"
api POST /profiles/switch "$(jq -n '{profile:"allowed"}')" | show >/dev/null
REV=$((REV + 1))
echo "切到 allowed 后 A webhook-a.demo.test（内置场景无此名，预期 NXDOMAIN）:"
if dns_query webhook-a.demo.test 2>/dev/null; then
  echo "意外成功"
  exit 1
fi
echo "    NXDOMAIN（符合预期）"
api POST /profiles/switch \
  "$(jq -n --argjson rev "$REV" '{profile:"custom", revision:$rev}')" | show >/dev/null
REV=$((REV + 1))
echo "切回 custom 后 A webhook-a.demo.test ->"
dns_query webhook-a.demo.test | sed 's/^/    /'

echo
echo "### 7. 最终控制面状态"
curl -sS "$CTRL/profiles" | jq '{revision, active, custom: .profiles.custom}'
echo
echo "核验完成。重启容器后可再次执行第一步，确认 revision/active/custom 已从卷中恢复。"
