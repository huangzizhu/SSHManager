from __future__ import annotations

import base64
import hashlib
import os

from cryptography.fernet import Fernet, InvalidToken


PBKDF2_ITERATIONS = 390000


class SecurityError(RuntimeError):
    pass


class CryptoManager:
    def __init__(self, secret_path: str) -> None:
        self.secret_path = secret_path

    def is_initialized(self) -> bool:
        return os.path.exists(self.secret_path)

    def initialize_master_password(self, master_password: str) -> None:
        if not master_password:
            raise SecurityError("Master password cannot be empty")
        if self.is_initialized():
            raise SecurityError("Master password already initialized")

        salt = os.urandom(16)
        verifier = self._derive_verifier(master_password, salt)
        os.makedirs(os.path.dirname(self.secret_path), exist_ok=True)
        with open(self.secret_path, "wb") as f:
            f.write(base64.urlsafe_b64encode(salt) + b"\n" + verifier.encode("utf-8") + b"\n")

    def verify_master_password(self, master_password: str) -> bool:
        salt, verifier = self._read_secret_file()
        return verifier == self._derive_verifier(master_password, salt)

    def encrypt(self, plaintext: str, master_password: str) -> str:
        fernet = Fernet(self._derive_fernet_key(master_password))
        return fernet.encrypt(plaintext.encode("utf-8")).decode("utf-8")

    def decrypt(self, ciphertext: str, master_password: str) -> str:
        fernet = Fernet(self._derive_fernet_key(master_password))
        try:
            return fernet.decrypt(ciphertext.encode("utf-8")).decode("utf-8")
        except InvalidToken as exc:
            raise SecurityError("Invalid master password or ciphertext") from exc

    def _read_secret_file(self) -> tuple[bytes, str]:
        if not self.is_initialized():
            raise SecurityError("Master password not initialized")
        with open(self.secret_path, "rb") as f:
            lines = f.read().splitlines()
        if len(lines) < 2:
            raise SecurityError("Master secret file is corrupted")
        return base64.urlsafe_b64decode(lines[0]), lines[1].decode("utf-8")

    def _derive_verifier(self, password: str, salt: bytes) -> str:
        data = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
        return base64.urlsafe_b64encode(data).decode("utf-8")

    def _derive_fernet_key(self, password: str) -> bytes:
        salt, _ = self._read_secret_file()
        key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
        return base64.urlsafe_b64encode(key)
