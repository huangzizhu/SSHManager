from __future__ import annotations

def run_cli() -> None:
    from sshmanager.cli.app import cli_app

    cli_app()


def run_gui_app() -> None:
    from sshmanager.context import get_crypto, get_repository
    from sshmanager.ui.main_window import run_gui

    run_gui(get_repository(), get_crypto())
