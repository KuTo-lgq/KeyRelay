from __future__ import annotations

import base64
import ipaddress
import json
import os
import socket
from pathlib import Path
from urllib.parse import urlparse

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def load_or_create_secret(path: Path, size: int = 32) -> bytes:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        return path.read_bytes()
    secret = os.urandom(size)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as file:
        file.write(secret)
    return secret


class VaultCipher:
    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError("The vault key must be 32 bytes")
        self._cipher = AESGCM(key)

    def encrypt(self, value: dict[str, str]) -> str:
        nonce = os.urandom(12)
        plaintext = json.dumps(value, separators=(",", ":")).encode()
        ciphertext = self._cipher.encrypt(nonce, plaintext, b"keyrelay:v1")
        return base64.urlsafe_b64encode(nonce + ciphertext).decode()

    def decrypt(self, value: str) -> dict[str, str]:
        payload = base64.urlsafe_b64decode(value.encode())
        plaintext = self._cipher.decrypt(payload[:12], payload[12:], b"keyrelay:v1")
        return json.loads(plaintext)


def validate_login_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("登录地址必须是完整的 HTTPS 地址")
    if parsed.username or parsed.password:
        raise ValueError("登录地址不能包含用户名或密码")
    return url


def host_is_public(hostname: str) -> bool:
    """Reject local/private targets to keep an agent from using KeyRelay as an SSRF proxy."""
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(hostname, None)}
    except socket.gaierror:
        return False
    return bool(addresses) and all(
        not (
            (address := ipaddress.ip_address(ip)).is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_reserved
        )
        for ip in addresses
    )
