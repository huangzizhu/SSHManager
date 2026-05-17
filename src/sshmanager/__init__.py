from __future__ import annotations

import sys

def main() -> None:
    from sshmanager.app import run_cli, run_gui_app

    if len(sys.argv) == 1:
        run_gui_app()
        return
    run_cli()
