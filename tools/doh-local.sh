#!/bin/bash
# Local DoH resolver — bypasses ISP DNS poisoning.
# Listens on 127.0.0.1:1053 (UDP/TCP), forwards via Cloudflare DoH (1.1.1.1 /dns-query).
set -euo pipefail

PORT="${DOH_PORT:-1053}"
DOH_URL_PATH="/dns-query"
DOH_HOST="cloudflare-dns.com"
DOH_IP="${DOH_IP:-1.1.1.1}"

log() { printf '[doh-local] %s\n' "$*" >&2; }

if ! command -v dig >/dev/null; then
  log "dig not found"; exit 1
fi

# Ensure systemd-resolved is NOT hogging 1053; we bind ourselves.
# Runtime dir for temp files
RUNDIR="${XDG_RUNTIME_DIR:-/tmp}/doh-local-$$"
mkdir -p "$RUNDIR"
trap 'rm -rf "$RUNDIR"' EXIT

# Process one DNS message (binary on stdin) → response on stdout
handle_one() {
  local q="$RUNDIR/q.bin" a="$RUNDIR/a.bin" r="$RUNDIR/r.bin"
  cat >"$q"
  local len
  len=$(wc -c <"$q")
  if [ "$len" -lt 12 ]; then
    return 1
  fi
  # base64url encode query for GET (RFC 8484)
  local b64
  b64=$(base64 -w0 "$q" | tr '+/' '-_' | tr -d '=')
  # Use curl for TLS + HTTP/2
  if curl -sS --max-time 5 --http2 \
      -H "accept: application/dns-message" \
      "https://${DOH_IP}${DOH_URL_PATH}?dns=${b64}" \
      -o "$a" 2>"$RUNDIR/err"; then
    local alen
    alen=$(wc -c <"$a")
    if [ "$alen" -ge 12 ]; then
      cat "$a"
      return 0
    fi
  fi
  # Fallback: dig +tcp to upstream (may be poisoned — last resort)
  # Extract QNAME roughly via dig @1.1.1.1 using the original query is hard;
  # just fail so caller can fall back.
  return 1
}

log "starting on 127.0.0.1:${PORT} → DoH ${DOH_IP} (${DOH_HOST})"

# UDP loop using socat-like approach with dig? Better: use a small python helper
# if available; else pure bash is too slow. Prefer python3.
if command -v python3 >/dev/null; then
  exec python3 -u - <<'PY' "$PORT" "$DOH_IP"
import sys, socket, struct, base64, urllib.request, ssl, threading

PORT = int(sys.argv[1])
DOH_IP = sys.argv[2]
DOH_HOST = "cloudflare-dns.com"
DOH_URL = f"https://{DOH_IP}/dns-query"

ctx = ssl.create_default_context()

def doh_query(payload: bytes) -> bytes:
    b64 = base64.urlsafe_b64encode(payload).rstrip(b"=").decode()
    url = f"{DOH_URL}?dns={b64}"
    req = urllib.request.Request(url, headers={"accept": "application/dns-message"})
    with urllib.request.urlopen(req, context=ctx, timeout=5) as resp:
        return resp.read()

def handle_udp(data: bytes, addr, sock):
    try:
        resp = doh_query(data)
        if resp:
            sock.sendto(resp, addr)
    except Exception as e:
        # SERVFAIL
        if len(data) >= 4:
            fail = bytearray(data[:2] + b"\x81\x82" + data[4:])
            # force RCODE=2 if not already error
            try:
                sock.sendto(bytes(fail), addr)
            except Exception:
                pass

def udp_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", PORT))
    print(f"[doh-local] UDP :{PORT} up", flush=True)
    while True:
        try:
            data, addr = s.recvfrom(4096)
        except InterruptedError:
            continue
        if len(data) < 12:
            continue
        threading.Thread(target=handle_udp, args=(data, addr, s), daemon=True).start()

def handle_tcp(conn):
    try:
        hdr = b""
        while len(hdr) < 2:
            chunk = conn.recv(2 - len(hdr))
            if not chunk:
                return
            hdr += chunk
        ln = struct.unpack("!H", hdr)[0]
        body = b""
        while len(body) < ln:
            chunk = conn.recv(ln - len(body))
            if not chunk:
                return
            body += chunk
        resp = doh_query(body)
        conn.sendall(struct.pack("!H", len(resp)) + resp)
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass

def tcp_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", PORT))
    s.listen(64)
    print(f"[doh-local] TCP :{PORT} up", flush=True)
    while True:
        conn, _ = s.accept()
        threading.Thread(target=handle_tcp, args=(conn,), daemon=True).start()

t = threading.Thread(target=tcp_server, daemon=True)
t.start()
udp_server()
PY
fi

log "no python3 — cannot serve"; exit 1
