#!/usr/bin/env python3
"""Prepare/apply a verified offline code update; preserve all user state."""
import argparse
from pathlib import Path
from ft_update_install import prepare, apply, recover_or_rollback, status

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("status", "prepare", "apply", "recover", "rollback", "cancel"))
    parser.add_argument("--service", action="store_true", help="Gracefully stop/restart a managed Vaultkeeper service")
    parser.add_argument("--user-service", action="store_true", help="Not supported for Vaultkeeper")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    try:
        if args.user_service and not args.service: raise ValueError("--user-service requires --service")
        if args.service and args.command not in ("apply", "cancel"): raise ValueError("--service is only supported with apply or cancel")
        if args.command == "status":
            import json
            print(json.dumps(status(root), indent=2))
        elif args.command == "prepare":
            prepare(root)
            from update_artifacts import prepare_artifacts
            prepare_artifacts(root)
        elif args.command == "apply" and args.service:
            from ft_update_service import apply_service
            apply_service(root, user=args.user_service)
        elif args.command == "apply": apply(root)
        elif args.command == "cancel" and args.service:
            from ft_update_service import cancel_service
            cancel_service(root, user=args.user_service)
        elif args.command == "cancel": raise ValueError("Use cancel --service for pending node maintenance")
        else: recover_or_rollback(root, rollback=args.command == "rollback")
    except Exception as exc:
        print("Update stopped: " + (str(exc) if isinstance(exc, (ValueError, PermissionError)) else type(exc).__name__))
        raise SystemExit(1)
