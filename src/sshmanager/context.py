from __future__ import annotations

import os
from pathlib import Path

from sshmanager.security.crypto import CryptoManager
from sshmanager.storage.repository import SQLiteRepository

APP_DIR = Path.home() / ".sshmanager"
DB_PATH = str(APP_DIR / "sshmanager.db")
SECRET_PATH = str(APP_DIR / "master.secret")


def get_repository() -> SQLiteRepository:
    os.makedirs(APP_DIR, exist_ok=True)
    return SQLiteRepository(DB_PATH)


def get_crypto() -> CryptoManager:
    os.makedirs(APP_DIR, exist_ok=True)
    return CryptoManager(SECRET_PATH)
