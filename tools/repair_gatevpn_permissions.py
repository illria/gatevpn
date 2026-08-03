#!/usr/bin/env python3
"""Repair permissions for GateVPN files that can contain profiles or secrets."""

from __future__ import annotations

import argparse
import shlex
from pathlib import Path


SENSITIVE_DATA_FILES = (
    "nodes.json",
    "publicvpnlist_cache.json",
    "vpngate_auth.txt",
    "ui_auth.json",
)


def read_environment_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return values
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        key, raw_value = line.split("=", 1)
        key = key.strip()
        if not key or not key.replace("_", "").isalnum():
            continue
        try:
            parts = shlex.split(raw_value, comments=True, posix=True)
            values[key] = parts[0] if parts else ""
        except ValueError:
            values[key] = raw_value.strip().strip("'\"")
    return values


def resolve_data_directory(install_dir: Path, env_file: Path, legacy_env_file: Path) -> Path:
    values = read_environment_file(legacy_env_file)
    values.update(read_environment_file(env_file))
    configured = values.get("VPNGATE_DATA_DIR", "").strip()
    if not configured:
        return install_dir / "vpngate_data"
    configured_path = Path(configured).expanduser()
    if not configured_path.is_absolute():
        configured_path = install_dir / configured_path
    return configured_path


def _chmod_existing_regular_file(path: Path, mode: int) -> bool:
    if not path.exists():
        return True
    if path.is_symlink() or not path.is_file():
        return False
    try:
        path.chmod(mode)
        return True
    except OSError:
        return False


def repair_runtime_permissions(install_dir: Path, env_file: Path, legacy_env_file: Path) -> bool:
    data_dir = resolve_data_directory(install_dir, env_file, legacy_env_file)
    config_dir = data_dir / "configs"
    success = True
    if config_dir.exists():
        if config_dir.is_symlink() or not config_dir.is_dir():
            success = False
        else:
            try:
                config_dir.chmod(0o700)
            except OSError:
                success = False
    for filename in SENSITIVE_DATA_FILES:
        success = _chmod_existing_regular_file(data_dir / filename, 0o600) and success
    if config_dir.is_dir() and not config_dir.is_symlink():
        try:
            config_files = list(config_dir.iterdir())
        except OSError:
            config_files = []
            success = False
        for path in config_files:
            if path.suffix.lower() not in {".ovpn", ".auth"}:
                continue
            success = _chmod_existing_regular_file(path, 0o600) and success
    return success


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--install-dir", required=True, type=Path)
    parser.add_argument("--env-file", required=True, type=Path)
    parser.add_argument("--legacy-env-file", required=True, type=Path)
    args = parser.parse_args()
    return 0 if repair_runtime_permissions(args.install_dir, args.env_file, args.legacy_env_file) else 1


if __name__ == "__main__":
    raise SystemExit(main())
