from pathlib import Path

import pytest

from keyrelay.security import VaultCipher, load_or_create_secret, validate_login_url


def test_vault_round_trip_does_not_contain_plaintext():
    cipher = VaultCipher(b"k" * 32)
    encrypted = cipher.encrypt({"username": "me@example.com", "password": "super-secret"})

    assert "super-secret" not in encrypted
    assert cipher.decrypt(encrypted) == {
        "username": "me@example.com",
        "password": "super-secret",
    }


def test_secret_is_created_once_with_restricted_permissions(tmp_path: Path):
    path = tmp_path / "secret"
    first = load_or_create_secret(path)
    second = load_or_create_secret(path)

    assert first == second
    assert len(first) == 32
    assert path.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com/login",
        "https://user:password@example.com/login",
        "javascript:alert(1)",
        "not-a-url",
    ],
)
def test_rejects_unsafe_login_urls(url: str):
    with pytest.raises(ValueError):
        validate_login_url(url)


def test_accepts_https_login_url():
    assert validate_login_url("https://example.com/login") == "https://example.com/login"
