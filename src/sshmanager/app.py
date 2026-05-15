from __future__ import annotations

from sshmanager.cli.app import cli_app
from sshmanager.context import get_crypto, get_repository
from sshmanager.ui.main_window import run_gui


def run_cli() -> None:
    cli_app()


def run_gui_app() -> None:
    run_gui(get_repository(), get_crypto())
