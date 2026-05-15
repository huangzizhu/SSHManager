from __future__ import annotations

import asyncio
import socket
from dataclasses import dataclass, field

import asyncssh

from sshmanager.models import (
    CheckItemResult,
    CommandResult,
    ConnectionOptions,
    ConnectionResult,
    DiagnosticReport,
    FixReport,
    ForwardRule,
    ForwardType,
    RuleCheckResult,
    ServerProfile,
)


@dataclass
class ActiveConnection:
    server_id: int
    conn: asyncssh.SSHClientConnection
    listeners: list[asyncssh.SSHListener] = field(default_factory=list)
    shell: asyncssh.SSHClientProcess | None = None
    output_queue: asyncio.Queue[str] = field(default_factory=asyncio.Queue)
    reader_task: asyncio.Task | None = None


class SSHService:
    def __init__(self) -> None:
        self._active: dict[int, ActiveConnection] = {}

    async def connect(
        self,
        server: ServerProfile,
        *,
        password: str | None,
        private_key_passphrase: str | None,
        options: ConnectionOptions,
        jump_server: ServerProfile | None = None,
        jump_password: str | None = None,
        jump_private_key_passphrase: str | None = None,
    ) -> ConnectionResult:
        kwargs = {
            "host": server.host,
            "port": server.port,
            "username": server.username,
            "known_hosts": None,
            "connect_timeout": options.timeout,
            "keepalive_interval": options.keepalive_interval,
        }
        if server.auth_type.value == "password":
            kwargs["password"] = password
        elif server.private_key_path:
            kwargs["client_keys"] = [server.private_key_path]
            if private_key_passphrase:
                kwargs["passphrase"] = private_key_passphrase

        if jump_server:
            jump_kwargs = {
                "host": jump_server.host,
                "port": jump_server.port,
                "username": jump_server.username,
                "known_hosts": None,
            }
            if jump_server.auth_type.value == "password":
                jump_kwargs["password"] = jump_password
            elif jump_server.private_key_path:
                jump_kwargs["client_keys"] = [jump_server.private_key_path]
                if jump_private_key_passphrase:
                    jump_kwargs["passphrase"] = jump_private_key_passphrase
            jump = await asyncssh.connect(**jump_kwargs)
            kwargs["tunnel"] = jump

        try:
            conn = await asyncssh.connect(**kwargs)
            self._active[server.id or -1] = ActiveConnection(server_id=server.id or -1, conn=conn)
            return ConnectionResult(success=True, message=f"Connected to {server.host}:{server.port}")
        except (OSError, asyncssh.Error) as exc:
            return ConnectionResult(success=False, message=str(exc))

    async def apply_forward_rules(self, server_id: int, rules: list[ForwardRule]) -> list[str]:
        active = self._active.get(server_id)
        if not active:
            return ["No active connection"]

        messages: list[str] = []
        for rule in rules:
            if not rule.enabled:
                continue
            try:
                if rule.type == ForwardType.LOCAL:
                    listener = await active.conn.forward_local_port(
                        rule.bind_host, rule.bind_port, rule.target_host or "127.0.0.1", rule.target_port or 0
                    )
                elif rule.type == ForwardType.REMOTE:
                    listener = await active.conn.forward_remote_port(
                        rule.bind_host, rule.bind_port, rule.target_host or "127.0.0.1", rule.target_port or 0
                    )
                else:
                    listener = await active.conn.forward_socks(rule.bind_host, rule.bind_port)
                active.listeners.append(listener)
                messages.append(f"Forward rule {rule.id or '-'} started ({rule.type.value})")
            except (OSError, asyncssh.Error) as exc:
                messages.append(f"Forward rule {rule.id or '-'} failed: {exc}")
        return messages

    async def check_forward_rules(self, server_id: int, rules: list[ForwardRule]) -> list[RuleCheckResult]:
        results: list[RuleCheckResult] = []
        active = self._active.get(server_id)
        if not active:
            return [RuleCheckResult(rule_id=None, type=ForwardType.LOCAL, ok=False, detail="No active connection")]

        for rule in rules:
            if not rule.enabled:
                results.append(RuleCheckResult(rule_id=rule.id, type=rule.type, ok=True, detail="Disabled rule skipped"))
                continue

            if rule.type == ForwardType.LOCAL:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1.0)
                try:
                    sock.connect((rule.bind_host, rule.bind_port))
                    results.append(RuleCheckResult(rule_id=rule.id, type=rule.type, ok=True, detail="Local listening OK"))
                except OSError as exc:
                    results.append(RuleCheckResult(rule_id=rule.id, type=rule.type, ok=False, detail=f"Local port not reachable: {exc}"))
                finally:
                    sock.close()
            elif rule.type == ForwardType.REMOTE:
                results.append(RuleCheckResult(rule_id=rule.id, type=rule.type, ok=True, detail="Remote forward created (server-side check limited)"))
            else:
                results.append(RuleCheckResult(rule_id=rule.id, type=rule.type, ok=True, detail="SOCKS listener created"))

        if hasattr(active.conn, "is_closing") and active.conn.is_closing():
            results.append(RuleCheckResult(rule_id=None, type=ForwardType.LOCAL, ok=False, detail="SSH connection is closing"))
        elif hasattr(active.conn, "is_closed") and active.conn.is_closed():
            results.append(RuleCheckResult(rule_id=None, type=ForwardType.LOCAL, ok=False, detail="SSH connection is closing"))
        return results

    async def open_interactive_shell(self, server_id: int) -> str:
        active = self._active.get(server_id)
        if not active:
            return "No active connection"

        if active.shell is not None:
            return "Interactive shell already started"

        shell = await active.conn.create_process(term_type="xterm", encoding="utf-8")
        active.shell = shell

        async def _reader() -> None:
            if not active.shell:
                return
            while True:
                chunk = await active.shell.stdout.read(2048)
                if not chunk:
                    break
                await active.output_queue.put(chunk)

        active.reader_task = asyncio.create_task(_reader())
        return "Interactive shell opened"

    async def send_input(self, server_id: int, data: str) -> None:
        active = self._active.get(server_id)
        if not active or not active.shell:
            return
        active.shell.stdin.write(data)
        await active.shell.stdin.drain()

    async def send_control(self, server_id: int, code: str) -> None:
        active = self._active.get(server_id)
        if not active or not active.shell:
            return
        if len(code) != 1:
            return
        ch = chr(ord(code.lower()) & 0x1F)
        active.shell.stdin.write(ch)
        await active.shell.stdin.drain()

    def is_shell_alive(self, server_id: int) -> bool:
        active = self._active.get(server_id)
        if not active or not active.shell:
            return False
        # Avoid relying on version-specific AsyncSSH status APIs.
        # Consider shell alive when connection is open and reader task is still running.
        if hasattr(active.conn, "is_closing") and active.conn.is_closing():
            return False
        if hasattr(active.conn, "is_closed") and active.conn.is_closed():
            return False
        if active.reader_task is not None and active.reader_task.done():
            return False
        return True

    async def read_output(self, server_id: int) -> str:
        active = self._active.get(server_id)
        if not active:
            return ""
        parts: list[str] = []
        while not active.output_queue.empty():
            parts.append(active.output_queue.get_nowait())
        return "".join(parts)

    async def run_command(self, server_id: int, command: str) -> str:
        active = self._active.get(server_id)
        if not active:
            return "No active connection"
        result = await active.conn.run(command, check=False)
        return result.stdout if result.stdout else result.stderr

    async def exec_commands(self, server: ServerProfile, password: str, commands: list[str]) -> CommandResult:
        outputs: list[str] = []
        try:
            conn = await asyncssh.connect(
                server.host,
                port=server.port,
                username=server.username,
                password=password,
                known_hosts=None,
            )
            try:
                for cmd in commands:
                    result = await conn.run(cmd, check=False)
                    if result.exit_status != 0:
                        stderr = result.stderr.strip() if result.stderr else f"command failed: {cmd}"
                        return CommandResult(success=False, outputs=outputs, error=stderr)
                    text = result.stdout.strip() if result.stdout else ""
                    if text:
                        outputs.append(text)
            finally:
                conn.close()
                await conn.wait_closed()
            return CommandResult(success=True, outputs=outputs)
        except (OSError, asyncssh.Error) as exc:
            return CommandResult(success=False, outputs=outputs, error=str(exc))

    async def diagnose_pubkey_auth(
        self, server: ServerProfile, password: str | None, public_key_text: str
    ) -> DiagnosticReport:
        items: list[CheckItemResult] = []
        sshd_effective: dict[str, str] = {}
        hints: list[str] = []
        try:
            conn = await self._connect_direct(server, password=password)
            try:
                user_check_cmd = (
                    "bash -lc \""
                    "test -d ~/.ssh && echo SSH_DIR_OK || echo SSH_DIR_MISSING; "
                    "test -f ~/.ssh/authorized_keys && echo AK_OK || echo AK_MISSING; "
                    "stat -c '%a %U:%G' ~/.ssh 2>/dev/null || true; "
                    "stat -c '%a %U:%G' ~/.ssh/authorized_keys 2>/dev/null || true\""
                )
                user_check = await conn.run(user_check_cmd, check=False)
                user_lines = (user_check.stdout or "").splitlines()
                items.append(CheckItemResult(name="~/.ssh exists", ok="SSH_DIR_OK" in user_lines, detail=(user_lines[0] if user_lines else "")))
                items.append(CheckItemResult(name="authorized_keys exists", ok="AK_OK" in user_lines, detail=(user_lines[1] if len(user_lines) > 1 else "")))
                if len(user_lines) > 2:
                    items.append(CheckItemResult(name="~/.ssh perms", ok=user_lines[2].startswith("700 "), detail=user_lines[2]))
                if len(user_lines) > 3:
                    items.append(CheckItemResult(name="authorized_keys perms", ok=user_lines[3].startswith("600 "), detail=user_lines[3]))

                quoted = public_key_text.replace("'", "'\"'\"'")
                key_check = await conn.run(
                    f"bash -lc \"grep -qxF '{quoted}' ~/.ssh/authorized_keys 2>/dev/null && echo KEY_OK || echo KEY_MISSING\"",
                    check=False,
                )
                key_ok = "KEY_OK" in (key_check.stdout or "")
                items.append(CheckItemResult(name="public key installed", ok=key_ok, detail=(key_check.stdout or key_check.stderr or "").strip()))

                sudo_ready = await conn.run("sudo -n true >/dev/null 2>&1", check=False)
                can_auto_fix = sudo_ready.exit_status == 0
                items.append(CheckItemResult(name="sudo available", ok=can_auto_fix, detail="sudo -n true"))

                if can_auto_fix:
                    t_cmd = (
                        "sudo sshd -T 2>/dev/null | "
                        "egrep '^(pubkeyauthentication|passwordauthentication|authorizedkeysfile|authenticationmethods) ' || true"
                    )
                    t_out = await conn.run(t_cmd, check=False)
                    for line in (t_out.stdout or "").splitlines():
                        parts = line.strip().split(None, 1)
                        if len(parts) == 2:
                            sshd_effective[parts[0]] = parts[1]
                    pubkey_enabled = sshd_effective.get("pubkeyauthentication", "no").lower() == "yes"
                    items.append(CheckItemResult(name="sshd pubkeyauthentication", ok=pubkey_enabled, detail=sshd_effective.get("pubkeyauthentication", "unknown")))
                    pwd_enabled = sshd_effective.get("passwordauthentication", "unknown")
                    items.append(CheckItemResult(name="sshd passwordauthentication", ok=True, detail=pwd_enabled))

                    hint_out = await conn.run(
                        "sudo sh -lc \"grep -RnsE '^[[:space:]]*(Match|PubkeyAuthentication|PasswordAuthentication|AuthorizedKeysFile|AuthenticationMethods)' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null || true\"",
                        check=False,
                    )
                    hints = [ln.strip() for ln in (hint_out.stdout or "").splitlines() if ln.strip()]
            finally:
                conn.close()
                await conn.wait_closed()
        except (OSError, asyncssh.Error) as exc:
            items.append(CheckItemResult(name="diagnose connect", ok=False, detail=str(exc)))
            return DiagnosticReport(ok=False, can_auto_fix=False, items=items, sshd_effective=sshd_effective, raw_sshd_config_hints=hints)

        overall_ok = all(i.ok for i in items if i.name not in {"sshd passwordauthentication"})
        return DiagnosticReport(
            ok=overall_ok,
            can_auto_fix=any(i.name == "sudo available" and i.ok for i in items),
            items=items,
            sshd_effective=sshd_effective,
            raw_sshd_config_hints=hints,
        )

    async def fix_pubkey_auth(
        self, server: ServerProfile, password: str | None, public_key_text: str
    ) -> FixReport:
        items: list[CheckItemResult] = []
        quoted = public_key_text.replace("'", "'\"'\"'")
        backup_path = f"/etc/ssh/sshd_config.sshmanager.bak"
        manual_commands = [
            f"sudo cp -an /etc/ssh/sshd_config {backup_path}",
            "sudoedit /etc/ssh/sshd_config",
            "sudo sshd -t && sudo systemctl reload ssh",
        ]
        try:
            conn = await self._connect_direct(server, password=password)
            try:
                user_cmd = (
                    "bash -lc \""
                    "umask 077; mkdir -p ~/.ssh; touch ~/.ssh/authorized_keys; "
                    "chmod 700 ~/.ssh; chmod 600 ~/.ssh/authorized_keys; chmod go-w ~ || true; "
                    f"grep -qxF '{quoted}' ~/.ssh/authorized_keys 2>/dev/null || echo '{quoted}' >> ~/.ssh/authorized_keys\""
                )
                user_fix = await conn.run(user_cmd, check=False)
                items.append(CheckItemResult(name="user-level fix", ok=user_fix.exit_status == 0, detail=(user_fix.stderr or "ok").strip()))
                if user_fix.exit_status != 0:
                    return FixReport(
                        ok=False,
                        user_fix_ok=False,
                        system_fix_ok=False,
                        system_fix_skipped=True,
                        items=items,
                        manual_commands=manual_commands,
                        detail=(user_fix.stderr or "user-level fix failed").strip(),
                    )
                user_ok = True

                sudo_ready = await conn.run("sudo -n true >/dev/null 2>&1", check=False)
                if sudo_ready.exit_status != 0:
                    items.append(CheckItemResult(name="system-level fix", ok=False, detail="sudo not available, skipped"))
                    return FixReport(
                        ok=True,
                        user_fix_ok=user_ok,
                        system_fix_ok=False,
                        system_fix_skipped=True,
                        items=items,
                        manual_commands=manual_commands,
                        backup_path=backup_path,
                        detail="system-level fix skipped: sudo not available",
                    )

                sys_cmd = (
                    "sudo sh -lc \""
                    f"cp -an /etc/ssh/sshd_config {backup_path} 2>/dev/null || true; "
                    "grep -Eq '^[[:space:]]*PubkeyAuthentication[[:space:]]+yes([[:space:]]|$)' /etc/ssh/sshd_config || "
                    "echo 'PubkeyAuthentication yes' >> /etc/ssh/sshd_config; "
                    "grep -Eq '^[[:space:]]*AuthorizedKeysFile[[:space:]]+' /etc/ssh/sshd_config || "
                    "echo 'AuthorizedKeysFile .ssh/authorized_keys' >> /etc/ssh/sshd_config\""
                )
                sys_fix = await conn.run(sys_cmd, check=False)
                items.append(CheckItemResult(name="system-level fix", ok=sys_fix.exit_status == 0, detail=(sys_fix.stderr or "ok").strip()))
                if sys_fix.exit_status != 0:
                    return FixReport(
                        ok=True,
                        user_fix_ok=user_ok,
                        system_fix_ok=False,
                        system_fix_skipped=False,
                        items=items,
                        manual_commands=manual_commands,
                        backup_path=backup_path,
                        detail=(sys_fix.stderr or "system-level fix failed").strip(),
                    )
            finally:
                conn.close()
                await conn.wait_closed()
        except (OSError, asyncssh.Error) as exc:
            return FixReport(
                ok=False,
                user_fix_ok=False,
                system_fix_ok=False,
                system_fix_skipped=True,
                items=items,
                manual_commands=manual_commands,
                backup_path=backup_path,
                detail=str(exc),
            )
        return FixReport(
            ok=True,
            user_fix_ok=True,
            system_fix_ok=True,
            system_fix_skipped=False,
            items=items,
            manual_commands=manual_commands,
            backup_path=backup_path,
            detail="fix applied",
        )

    async def validate_and_reload_sshd(self, server: ServerProfile, password: str | None) -> tuple[bool, str]:
        try:
            conn = await self._connect_direct(server, password=password)
            try:
                test = await conn.run("sudo -n sshd -t", check=False)
                if test.exit_status != 0:
                    return False, (test.stderr or "sshd -t failed").strip()
                reload_res = await conn.run("sudo -n systemctl reload ssh || sudo -n systemctl reload sshd", check=False)
                if reload_res.exit_status != 0:
                    return False, (reload_res.stderr or "reload ssh service failed").strip()
                return True, "sshd config validated and reloaded"
            finally:
                conn.close()
                await conn.wait_closed()
        except (OSError, asyncssh.Error) as exc:
            return False, str(exc)

    async def test_private_key_login(self, server: ServerProfile, key_path: str) -> tuple[bool, str]:
        try:
            conn = await asyncssh.connect(
                server.host,
                port=server.port,
                username=server.username,
                client_keys=[key_path],
                known_hosts=None,
            )
            try:
                result = await conn.run("echo SSH_KEY_OK", check=False)
                if result.exit_status == 0 and "SSH_KEY_OK" in (result.stdout or ""):
                    return True, "Private key login verified"
                return False, (result.stderr or "private key login test command failed").strip()
            finally:
                conn.close()
                await conn.wait_closed()
        except (OSError, asyncssh.Error) as exc:
            return False, str(exc)

    async def disconnect(self, server_id: int) -> None:
        active = self._active.pop(server_id, None)
        if not active:
            return
        for listener in active.listeners:
            listener.close()
        if active.reader_task:
            active.reader_task.cancel()
        if active.shell:
            active.shell.close()
        active.conn.close()
        await active.conn.wait_closed()

    async def disconnect_all(self) -> None:
        for server_id in list(self._active):
            await self.disconnect(server_id)

    async def keepalive(self) -> None:
        while True:
            await asyncio.sleep(30)
            stale: list[int] = []
            for sid, active in self._active.items():
                if (hasattr(active.conn, "is_closing") and active.conn.is_closing()) or (
                    hasattr(active.conn, "is_closed") and active.conn.is_closed()
                ):
                    stale.append(sid)
            for sid in stale:
                self._active.pop(sid, None)
    async def _connect_direct(
        self,
        server: ServerProfile,
        *,
        password: str | None = None,
    ) -> asyncssh.SSHClientConnection:
        kwargs = {
            "host": server.host,
            "port": server.port,
            "username": server.username,
            "known_hosts": None,
        }
        if password:
            kwargs["password"] = password
        elif server.private_key_path:
            kwargs["client_keys"] = [server.private_key_path]
        return await asyncssh.connect(**kwargs)
