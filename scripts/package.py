from __future__ import annotations

import argparse
import platform
import shutil
from dataclasses import dataclass
from pathlib import Path

from PyInstaller.__main__ import run as pyinstaller_run

ROOT = Path(__file__).resolve().parent.parent


@dataclass(frozen=True)
class BuildJob:
    name: str
    entry: str
    windowed: bool = False


MACOS_ARCH_CHOICES = ("x86_64", "arm64", "universal2")


def _local_target() -> str:
    system = platform.system().lower()
    if system.startswith("win"):
        return "windows"
    if system == "linux":
        return "linux"
    if system == "darwin":
        return "macos"
    raise RuntimeError(f"Unsupported build host: {platform.system()}")


def _build_job(job: BuildJob, target: str, onefile: bool, target_arch: str | None) -> None:
    dist_root = ROOT / "dist" / target
    build_root = ROOT / "build" / target / job.name
    spec_root = ROOT / "build" / target / "spec"

    args = [
        "--noconfirm",
        "--clean",
        "--name",
        job.name,
        "--paths",
        str(ROOT / "src"),
        "--distpath",
        str(dist_root),
        "--workpath",
        str(build_root),
        "--specpath",
        str(spec_root),
    ]
    if onefile:
        args.append("--onefile")
    if job.windowed:
        args.append("--windowed")
    if target == "macos" and target_arch is not None:
        args.extend(["--target-arch", target_arch])
    args.append(str(ROOT / job.entry))
    pyinstaller_run(args)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Package SSHManager for the current operating system."
    )
    parser.add_argument(
        "--target",
        choices=("linux", "windows", "macos"),
        help="Build target. Must match the current host OS.",
    )
    parser.add_argument(
        "--mode",
        choices=("all", "gui", "cli"),
        default="all",
        help="Choose which executable(s) to build.",
    )
    parser.add_argument(
        "--onefile",
        action="store_true",
        help="Build one-file executables (larger startup overhead).",
    )
    parser.add_argument(
        "--clean-output",
        action="store_true",
        help="Delete dist/<target> and build/<target> before packaging.",
    )
    parser.add_argument(
        "--target-arch",
        choices=MACOS_ARCH_CHOICES,
        help="Target architecture for macOS builds.",
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    local_target = _local_target()
    target = args.target or local_target
    if target != local_target:
        raise SystemExit(
            f"PyInstaller does not cross-compile: run this on {target}, current host is {local_target}."
        )
    if args.target_arch is not None and target != "macos":
        raise SystemExit("--target-arch is only supported when --target macos is selected.")

    if args.clean_output:
        shutil.rmtree(ROOT / "dist" / target, ignore_errors=True)
        shutil.rmtree(ROOT / "build" / target, ignore_errors=True)

    jobs = []
    if args.mode in {"all", "gui"}:
        jobs.append(BuildJob(name="sshmanager-gui", entry="main_gui.py", windowed=True))
    if args.mode in {"all", "cli"}:
        jobs.append(BuildJob(name="sshmanager-cli", entry="main_cli.py"))

    for job in jobs:
        arch_suffix = f", target_arch={args.target_arch}" if target == "macos" and args.target_arch else ""
        print(f"==> Building {job.name} ({target}, onefile={args.onefile}{arch_suffix})")
        _build_job(job, target=target, onefile=args.onefile, target_arch=args.target_arch)

    print(f"Done. Output directory: {ROOT / 'dist' / target}")


if __name__ == "__main__":
    main()
