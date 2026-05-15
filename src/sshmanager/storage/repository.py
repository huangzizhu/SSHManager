from __future__ import annotations

import json
from datetime import datetime

import aiosqlite

from sshmanager.models import ConnectionOptions, ForwardRule, ServerProfile


class SQLiteRepository:
    def __init__(self, db_path: str) -> None:
        self.db_path = db_path

    async def init_db(self) -> None:
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("PRAGMA foreign_keys = ON")
            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS servers (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    host TEXT NOT NULL,
                    port INTEGER NOT NULL DEFAULT 22,
                    username TEXT NOT NULL,
                    auth_type TEXT NOT NULL,
                    password_enc TEXT,
                    private_key_path TEXT,
                    private_key_passphrase_enc TEXT,
                    jump_host_id INTEGER,
                    remark TEXT NOT NULL DEFAULT '',
                    remember_password INTEGER NOT NULL DEFAULT 1,
                    last_used_at TEXT,
                    FOREIGN KEY(jump_host_id) REFERENCES servers(id) ON DELETE SET NULL
                )
                """
            )
            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS forward_rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    server_id INTEGER NOT NULL,
                    type TEXT NOT NULL,
                    bind_host TEXT NOT NULL,
                    bind_port INTEGER NOT NULL,
                    target_host TEXT,
                    target_port INTEGER,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    last_used INTEGER NOT NULL DEFAULT 1,
                    FOREIGN KEY(server_id) REFERENCES servers(id) ON DELETE CASCADE
                )
                """
            )
            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS connection_options (
                    server_id INTEGER PRIMARY KEY,
                    options_json TEXT NOT NULL,
                    FOREIGN KEY(server_id) REFERENCES servers(id) ON DELETE CASCADE
                )
                """
            )
            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS app_settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
                """
            )
            await db.commit()

    async def list_servers(self) -> list[ServerProfile]:
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT * FROM servers ORDER BY name ASC")
            rows = await cursor.fetchall()
            return [self._row_to_server(row) for row in rows]

    async def get_server_by_id(self, server_id: int) -> ServerProfile | None:
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT * FROM servers WHERE id = ?", (server_id,))
            row = await cursor.fetchone()
            return self._row_to_server(row) if row else None

    async def get_server_by_name(self, name: str) -> ServerProfile | None:
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT * FROM servers WHERE name = ?", (name,))
            row = await cursor.fetchone()
            return self._row_to_server(row) if row else None

    async def upsert_server(self, server: ServerProfile) -> int:
        async with aiosqlite.connect(self.db_path) as db:
            if server.id is None:
                cursor = await db.execute(
                    """
                    INSERT INTO servers (
                        name, host, port, username, auth_type, password_enc,
                        private_key_path, private_key_passphrase_enc, jump_host_id,
                        remark, remember_password, last_used_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        server.name,
                        server.host,
                        server.port,
                        server.username,
                        server.auth_type.value,
                        server.password_enc,
                        server.private_key_path,
                        server.private_key_passphrase_enc,
                        server.jump_host_id,
                        server.remark,
                        int(server.remember_password),
                        server.last_used_at.isoformat() if server.last_used_at else None,
                    ),
                )
                await db.commit()
                return int(cursor.lastrowid)

            await db.execute(
                """
                UPDATE servers SET
                    name=?, host=?, port=?, username=?, auth_type=?, password_enc=?,
                    private_key_path=?, private_key_passphrase_enc=?, jump_host_id=?,
                    remark=?, remember_password=?, last_used_at=?
                WHERE id=?
                """,
                (
                    server.name,
                    server.host,
                    server.port,
                    server.username,
                    server.auth_type.value,
                    server.password_enc,
                    server.private_key_path,
                    server.private_key_passphrase_enc,
                    server.jump_host_id,
                    server.remark,
                    int(server.remember_password),
                    server.last_used_at.isoformat() if server.last_used_at else None,
                    server.id,
                ),
            )
            await db.commit()
            return server.id

    async def delete_server(self, server_id: int) -> None:
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("DELETE FROM servers WHERE id = ?", (server_id,))
            await db.commit()

    async def list_forward_rules(self, server_id: int) -> list[ForwardRule]:
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                "SELECT * FROM forward_rules WHERE server_id = ? ORDER BY id ASC", (server_id,)
            )
            rows = await cursor.fetchall()
            return [self._row_to_forward(row) for row in rows]

    async def upsert_forward_rule(self, rule: ForwardRule) -> int:
        async with aiosqlite.connect(self.db_path) as db:
            if rule.id is None:
                cursor = await db.execute(
                    """
                    INSERT INTO forward_rules (
                        server_id, type, bind_host, bind_port, target_host,
                        target_port, enabled, last_used
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        rule.server_id,
                        rule.type.value,
                        rule.bind_host,
                        rule.bind_port,
                        rule.target_host,
                        rule.target_port,
                        int(rule.enabled),
                        int(rule.last_used),
                    ),
                )
                await db.commit()
                return int(cursor.lastrowid)

            await db.execute(
                """
                UPDATE forward_rules SET
                    server_id=?, type=?, bind_host=?, bind_port=?, target_host=?,
                    target_port=?, enabled=?, last_used=?
                WHERE id=?
                """,
                (
                    rule.server_id,
                    rule.type.value,
                    rule.bind_host,
                    rule.bind_port,
                    rule.target_host,
                    rule.target_port,
                    int(rule.enabled),
                    int(rule.last_used),
                    rule.id,
                ),
            )
            await db.commit()
            return rule.id

    async def delete_forward_rule(self, rule_id: int) -> None:
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("DELETE FROM forward_rules WHERE id = ?", (rule_id,))
            await db.commit()

    async def replace_forward_rules(self, server_id: int, rules: list[ForwardRule]) -> None:
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("DELETE FROM forward_rules WHERE server_id = ?", (server_id,))
            for rule in rules:
                await db.execute(
                    """
                    INSERT INTO forward_rules (
                        server_id, type, bind_host, bind_port, target_host,
                        target_port, enabled, last_used
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        server_id,
                        rule.type.value,
                        rule.bind_host,
                        rule.bind_port,
                        rule.target_host,
                        rule.target_port,
                        int(rule.enabled),
                        int(rule.last_used),
                    ),
                )
            await db.commit()

    async def save_connection_options(self, server_id: int, options: ConnectionOptions) -> None:
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT INTO connection_options (server_id, options_json)
                VALUES (?, ?)
                ON CONFLICT(server_id) DO UPDATE SET options_json=excluded.options_json
                """,
                (server_id, options.model_dump_json()),
            )
            await db.commit()

    async def get_connection_options(self, server_id: int) -> ConnectionOptions:
        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute(
                "SELECT options_json FROM connection_options WHERE server_id = ?", (server_id,)
            )
            row = await cursor.fetchone()
            if not row:
                return ConnectionOptions()
            return ConnectionOptions.model_validate(json.loads(row[0]))

    async def mark_server_used(self, server_id: int) -> None:
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "UPDATE servers SET last_used_at = ? WHERE id = ?",
                (datetime.utcnow().isoformat(), server_id),
            )
            await db.execute(
                "UPDATE forward_rules SET last_used = enabled WHERE server_id = ?",
                (server_id,),
            )
            await db.commit()

    async def get_setting(self, key: str, default: str | None = None) -> str | None:
        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute("SELECT value FROM app_settings WHERE key = ?", (key,))
            row = await cursor.fetchone()
            if not row:
                return default
            return row[0]

    async def set_setting(self, key: str, value: str) -> None:
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT INTO app_settings (key, value) VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                (key, value),
            )
            await db.commit()

    @staticmethod
    def _row_to_server(row: aiosqlite.Row) -> ServerProfile:
        return ServerProfile(
            id=row["id"],
            name=row["name"],
            host=row["host"],
            port=row["port"],
            username=row["username"],
            auth_type=row["auth_type"],
            password_enc=row["password_enc"],
            private_key_path=row["private_key_path"],
            private_key_passphrase_enc=row["private_key_passphrase_enc"],
            jump_host_id=row["jump_host_id"],
            remark=row["remark"],
            remember_password=bool(row["remember_password"]),
            last_used_at=datetime.fromisoformat(row["last_used_at"]) if row["last_used_at"] else None,
        )

    @staticmethod
    def _row_to_forward(row: aiosqlite.Row) -> ForwardRule:
        return ForwardRule(
            id=row["id"],
            server_id=row["server_id"],
            type=row["type"],
            bind_host=row["bind_host"],
            bind_port=row["bind_port"],
            target_host=row["target_host"],
            target_port=row["target_port"],
            enabled=bool(row["enabled"]),
            last_used=bool(row["last_used"]),
        )
