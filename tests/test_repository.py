from __future__ import annotations

import asyncio

from sshmanager.models import ConnectionOptions, ForwardRule, ForwardType, ServerProfile, TerminalMode
from sshmanager.storage.repository import SQLiteRepository


def test_repository_server_forward_and_options(tmp_path) -> None:
    async def _run() -> None:
        repo = SQLiteRepository(str(tmp_path / "test.db"))
        await repo.init_db()

        sid = await repo.upsert_server(
            ServerProfile(name="prod", host="1.2.3.4", username="root", remember_password=True)
        )
        assert sid > 0

        saved = await repo.get_server_by_id(sid)
        assert saved is not None
        assert saved.name == "prod"

        rid = await repo.upsert_forward_rule(
            ForwardRule(
                server_id=sid,
                type=ForwardType.LOCAL,
                bind_host="127.0.0.1",
                bind_port=15432,
                target_host="127.0.0.1",
                target_port=5432,
                enabled=True,
                last_used=True,
            )
        )
        assert rid > 0

        rules = await repo.list_forward_rules(sid)
        assert len(rules) == 1

        await repo.save_connection_options(sid, ConnectionOptions(terminal_mode=TerminalMode.SYSTEM))
        opts = await repo.get_connection_options(sid)
        assert opts.terminal_mode == TerminalMode.SYSTEM

        await repo.delete_server(sid)
        assert await repo.get_server_by_id(sid) is None

    asyncio.run(_run())
