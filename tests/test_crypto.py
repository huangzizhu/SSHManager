from __future__ import annotations

from pathlib import Path

import pytest

from sshmanager.security.crypto import CryptoManager, SecurityError


def test_crypto_encrypt_decrypt_roundtrip(tmp_path: Path) -> None:
    secret_path = tmp_path / "master.secret"
    crypto = CryptoManager(str(secret_path))
    crypto.initialize_master_password("master-123")

    cipher = crypto.encrypt("pässw0rd!@#", "master-123")
    plain = crypto.decrypt(cipher, "master-123")

    assert plain == "pässw0rd!@#"


def test_crypto_rejects_wrong_master_password(tmp_path: Path) -> None:
    secret_path = tmp_path / "master.secret"
    crypto = CryptoManager(str(secret_path))
    crypto.initialize_master_password("good-pass")
    cipher = crypto.encrypt("abc", "good-pass")

    with pytest.raises(SecurityError):
        crypto.decrypt(cipher, "bad-pass")
