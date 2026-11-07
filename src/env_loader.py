"""Lightweight zero-dependency .env loader for SwitchGate Lite."""
import os
import pathlib
from typing import Iterable


def load_local_env(extra_paths: Iterable[str] = ()) -> None:
    """Loads key=value pairs from local .env files into os.environ if not already set."""
    root = pathlib.Path(__file__).resolve().parent.parent
    candidates = [
        root / ".env",
        root / "config" / ".env",
        root.parent / ".env",
        root.parent / "switch-server" / ".env",
    ]
    for p_str in extra_paths:
        candidates.append(pathlib.Path(p_str))

    for env_path in candidates:
        if not env_path.is_file():
            continue
        for raw_line in env_path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, val = line.split("=", 1)
            key = key.strip()
            val = val.strip().strip("'").strip('"')
            if key and key not in os.environ and val:
                os.environ[key] = val
