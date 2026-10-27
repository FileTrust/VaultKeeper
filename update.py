#!/usr/bin/env python3
"""Check signed application releases without changing the running app."""
from pathlib import Path
from core.ft_updates import cli

if __name__ == "__main__":
    raise SystemExit(cli(Path(__file__).resolve().parent))
