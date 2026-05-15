from __future__ import annotations

import base64
import hashlib
import os

from cryptography.fernet import Fernet, InvalidToken


PBKDF2_ITERATIONS = 390000


class ExportCryptoError(RuntimeError):
    pass


def generate_export_salt() -> str:
    return base64.urlsafe_b64encode(os.urandom(16)).decode("utf-8")


def _derive_fernet_key(passphrase: str, salt_b64: str) -> bytes:
    if not passphrase:
        raise ExportCryptoError("Export passphrase cannot be empty")
    salt = base64.urlsafe_b64decode(salt_b64.encode("utf-8"))
    key = hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return base64.urlsafe_b64encode(key)


def encrypt_for_export(plaintext: str, export_passphrase: str, salt_b64: str) -> str:
    fernet = Fernet(_derive_fernet_key(export_passphrase, salt_b64))
    return fernet.encrypt(plaintext.encode("utf-8")).decode("utf-8")


def decrypt_from_export(ciphertext: str, export_passphrase: str, salt_b64: str) -> str:
    fernet = Fernet(_derive_fernet_key(export_passphrase, salt_b64))
    try:
        return fernet.decrypt(ciphertext.encode("utf-8")).decode("utf-8")
    except InvalidToken as exc:
        raise ExportCryptoError("Invalid export passphrase or ciphertext") from exc
