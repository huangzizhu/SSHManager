from __future__ import annotations

import os
import platform
import shlex
import shutil
import subprocess

from sshmanager.models import ServerProfile


def build_ssh_command(server: ServerProfile) -> str:
    user_host = f"{server.username}@{server.host}"
    parts = ["ssh"]
    if server.private_key_path:
        parts.extend(["-i", shlex.quote(server.private_key_path)])
    parts.extend([shlex.quote(user_host), "-p", str(server.port)])
    return " ".join(parts)


def _check_ssh_available_windows() -> bool:
    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", "Get-Command ssh -ErrorAction SilentlyContinue"],
        capture_output=True,
        text=True,
        check=False,
    )
    return result.returncode == 0 and bool(result.stdout.strip())


def _build_login_shell_command(cmd: str) -> str:
    return f"if ! command -v ssh >/dev/null 2>&1; then echo 'ssh not found in login shell PATH'; exec $SHELL -l; fi; {cmd}; exec $SHELL -l"


def launch_system_terminal(server: ServerProfile) -> tuple[bool, str]:
    cmd = build_ssh_command(server)
    system = platform.system().lower()

    try:
        if "windows" in system:
            if not _check_ssh_available_windows():
                return False, "Windows terminal environment cannot find ssh command"
            terminal = shutil.which("wt")
            if terminal:
                subprocess.Popen([terminal, "powershell", "-NoExit", cmd], env=os.environ.copy())
                return True, "Started SSH in Windows Terminal"
            subprocess.Popen(["powershell", "-NoExit", cmd], env=os.environ.copy())
            return True, "Started SSH in PowerShell"

        check = subprocess.run(
            ["bash", "-lc", "command -v ssh >/dev/null 2>&1"],
            capture_output=True,
            text=True,
            check=False,
            env=os.environ.copy(),
        )
        if check.returncode != 0:
            return False, "Login shell environment cannot find ssh command"

        wrapped = _build_login_shell_command(cmd)
        for candidate in ("gnome-terminal", "konsole", "x-terminal-emulator", "xterm"):
            if not shutil.which(candidate):
                continue
            if candidate == "gnome-terminal":
                subprocess.Popen([candidate, "--", "bash", "-lc", wrapped], env=os.environ.copy())
            elif candidate == "konsole":
                subprocess.Popen([candidate, "-e", "bash", "-lc", wrapped], env=os.environ.copy())
            elif candidate == "xterm":
                subprocess.Popen([candidate, "-e", "bash", "-lc", wrapped], env=os.environ.copy())
            else:
                subprocess.Popen([candidate, "-e", "bash", "-lc", wrapped], env=os.environ.copy())
            return True, f"Started SSH in {candidate} (login shell)"

        return False, "No supported system terminal found"
    except Exception as exc:  # noqa: BLE001
        return False, f"Failed to start system terminal: {exc}"
