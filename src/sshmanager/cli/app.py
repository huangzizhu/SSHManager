from __future__ import annotations

import asyncio
from getpass import getpass

import typer
from rich.console import Console
from rich.table import Table

from sshmanager.context import get_crypto, get_repository
from sshmanager.core.ssh_service import SSHService
from sshmanager.models import AuthType, ConnectionOptions, ForwardType, ForwardRule, ServerProfile, TerminalMode

cli_app = typer.Typer(help="SSHManager CLI")
server_app = typer.Typer(help="Manage server profiles")
forward_app = typer.Typer(help="Manage forwarding")
cli_app.add_typer(server_app, name="server")
cli_app.add_typer(forward_app, name="forward")
console = Console()


def _run(coro):
    return asyncio.run(coro)


async def _ensure_master_password(crypto) -> str:
    if not crypto.is_initialized():
        first = getpass("Set master password: ")
        second = getpass("Confirm master password: ")
        if first != second:
            raise typer.BadParameter("Passwords do not match")
        crypto.initialize_master_password(first)
        return first

    password = getpass("Master password: ")
    if not crypto.verify_master_password(password):
        raise typer.BadParameter("Invalid master password")
    return password


def _resolve_server_id(value: str, servers: list[ServerProfile]) -> int:
    if value.isdigit():
        return int(value)
    for s in servers:
        if s.name == value:
            return s.id or -1
    raise typer.BadParameter(f"Server not found: {value}")


@cli_app.command("gui")
def gui() -> None:
    from sshmanager.ui.main_window import run_gui

    run_gui(get_repository(), get_crypto())


@server_app.command("list")
def list_servers() -> None:
    async def _list() -> None:
        repo = get_repository()
        await repo.init_db()
        servers = await repo.list_servers()

        table = Table(title="Servers")
        table.add_column("ID")
        table.add_column("Name")
        table.add_column("Host")
        table.add_column("User")
        table.add_column("Auth")

        for s in servers:
            table.add_row(str(s.id), s.name, f"{s.host}:{s.port}", s.username, s.auth_type.value)
        console.print(table)

    _run(_list())


@server_app.command("add")
def add_server(
    name: str = typer.Option(...),
    host: str = typer.Option(...),
    username: str = typer.Option(...),
    port: int = typer.Option(22),
    auth_type: AuthType = typer.Option(AuthType.PASSWORD),
    private_key_path: str | None = typer.Option(None),
    remark: str = typer.Option(""),
    remember_password: bool = typer.Option(True),
) -> None:
    async def _add() -> None:
        repo = get_repository()
        crypto = get_crypto()
        await repo.init_db()

        master = await _ensure_master_password(crypto)

        password_enc = None
        if auth_type == AuthType.PASSWORD and remember_password:
            password = getpass("SSH password: ")
            if password:
                password_enc = crypto.encrypt(password, master)

        profile = ServerProfile(
            name=name,
            host=host,
            port=port,
            username=username,
            auth_type=auth_type,
            password_enc=password_enc,
            private_key_path=private_key_path,
            remark=remark,
            remember_password=remember_password,
        )
        server_id = await repo.upsert_server(profile)
        console.print(f"[green]Server saved with id={server_id}[/green]")

    _run(_add())


@server_app.command("remove")
def remove_server(server: str) -> None:
    async def _remove() -> None:
        repo = get_repository()
        await repo.init_db()
        all_servers = await repo.list_servers()
        sid = _resolve_server_id(server, all_servers)
        await repo.delete_server(sid)
        console.print(f"[yellow]Removed server {sid}[/yellow]")

    _run(_remove())


@server_app.command("edit")
def edit_server(
    server: str,
    host: str | None = typer.Option(None),
    username: str | None = typer.Option(None),
    port: int | None = typer.Option(None),
    remark: str | None = typer.Option(None),
    remember_password: bool | None = typer.Option(None),
) -> None:
    async def _edit() -> None:
        repo = get_repository()
        await repo.init_db()
        all_servers = await repo.list_servers()
        sid = _resolve_server_id(server, all_servers)
        profile = await repo.get_server_by_id(sid)
        if not profile:
            raise typer.BadParameter("Server not found")
        if host is not None:
            profile.host = host
        if username is not None:
            profile.username = username
        if port is not None:
            profile.port = port
        if remark is not None:
            profile.remark = remark
        if remember_password is not None:
            profile.remember_password = remember_password
        await repo.upsert_server(profile)
        console.print(f"[green]Updated server {sid}[/green]")

    _run(_edit())


@cli_app.command("connect")
def connect(
    server: str,
    system_terminal: bool = typer.Option(False, "--system-terminal"),
    embedded: bool = typer.Option(False, "--embedded"),
    command: str = typer.Option("uname -a"),
) -> None:
    async def _connect() -> None:
        from sshmanager.core.terminal import launch_system_terminal

        repo = get_repository()
        crypto = get_crypto()
        ssh = SSHService()
        await repo.init_db()

        servers = await repo.list_servers()
        sid = _resolve_server_id(server, servers)
        profile = await repo.get_server_by_id(sid)
        if not profile:
            raise typer.BadParameter("Server not found")

        mode = TerminalMode.SYSTEM if system_terminal else TerminalMode.EMBEDDED
        if embedded:
            mode = TerminalMode.EMBEDDED

        if mode == TerminalMode.SYSTEM:
            ok, msg = launch_system_terminal(profile)
            console.print(msg if ok else f"[red]{msg}[/red]")
            return

        master = await _ensure_master_password(crypto)
        password = crypto.decrypt(profile.password_enc, master) if profile.password_enc else None
        jump_server = None
        jump_password = None
        if profile.jump_host_id:
            jump_server = await repo.get_server_by_id(profile.jump_host_id)
            if jump_server and jump_server.password_enc:
                jump_password = crypto.decrypt(jump_server.password_enc, master)
        result = await ssh.connect(
            profile,
            password=password,
            private_key_passphrase=None,
            options=ConnectionOptions(terminal_mode=mode),
            jump_server=jump_server,
            jump_password=jump_password,
        )
        if not result.success:
            console.print(f"[red]{result.message}[/red]")
            return

        outputs = await ssh.run_command(sid, command)
        console.print(outputs.strip() if outputs else "(no output)")

        rules = await repo.list_forward_rules(sid)
        if rules:
            messages = await ssh.apply_forward_rules(sid, [r for r in rules if r.last_used])
            for msg in messages:
                console.print(msg)

        await repo.mark_server_used(sid)
        await ssh.disconnect(sid)

    _run(_connect())


@forward_app.command("up")
def up(
    server: str,
    type: ForwardType = typer.Option(...),
    bind_host: str = typer.Option("127.0.0.1"),
    bind_port: int = typer.Option(...),
    target_host: str | None = typer.Option(None),
    target_port: int | None = typer.Option(None),
) -> None:
    async def _up() -> None:
        repo = get_repository()
        await repo.init_db()
        servers = await repo.list_servers()
        sid = _resolve_server_id(server, servers)

        rule = ForwardRule(
            server_id=sid,
            type=type,
            bind_host=bind_host,
            bind_port=bind_port,
            target_host=target_host,
            target_port=target_port,
            enabled=True,
            last_used=True,
        )
        rule_id = await repo.upsert_forward_rule(rule)
        console.print(f"[green]Forward rule saved: id={rule_id}[/green]")

    _run(_up())


@forward_app.command("down")
def down(server: str, rule: int = typer.Option(..., "--rule")) -> None:
    async def _down() -> None:
        repo = get_repository()
        await repo.init_db()
        servers = await repo.list_servers()
        sid = _resolve_server_id(server, servers)
        rules = await repo.list_forward_rules(sid)
        target = next((r for r in rules if r.id == rule), None)
        if not target:
            raise typer.BadParameter("Rule not found")
        target.enabled = False
        target.last_used = False
        await repo.upsert_forward_rule(target)
        console.print(f"[yellow]Forward rule disabled: id={rule}[/yellow]")

    _run(_down())
