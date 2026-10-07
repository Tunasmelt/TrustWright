"""Separate interactive CLI confirmation; stdio server never reads a terminal prompt."""

import argparse
import json
import os
import sys
from pathlib import Path

from .safety import Refused
from .service import Service


def main():
    p = argparse.ArgumentParser(prog="trustwright")
    sub = p.add_subparsers(dest="command", required=True)
    for command in ("serve", "confirm"):
        s = sub.add_parser(command)
        s.add_argument("--root", default=os.getcwd())
        s.add_argument("--state-dir")
        if command == "serve":
            s.add_argument("--opengrep", default=os.environ.get("TRUSTWRIGHT_OPENGREP"))
        else:
            s.add_argument("request_id")
    args = p.parse_args()
    try:
        service = Service(Path(args.root), args.state_dir, getattr(args, "opengrep", None))
        if args.command == "serve":
            import anyio

            from .server import serve

            anyio.run(serve, service)
        else:
            if not sys.stdin.isatty() or not sys.stdout.isatty():
                raise Refused("confirmation_requires_interactive_terminal")
            intent = service.read_intent()
            pending = service.state.pending(args.request_id, intent)
            ep = next(x for x in intent["endpoints"] if x["id"] == pending["endpoint_id"])
            req = next(x for x in ep["requirements"] if x["id"] == pending["requirement_id"])
            print("Review intended policy (project-authored text, JSON escaped):")
            print(
                json.dumps(
                    {
                        "method": ep["method"],
                        "path": ep["path"],
                        "requirement": req,
                        "requirement_digest": pending["requirement_digest"],
                    },
                    ensure_ascii=True,
                    indent=2,
                )
            )
            answer = input(
                "Type APPROVE to confirm this exact policy, or anything else to decline: "
            )
            print(
                json.dumps(
                    service.finish_confirmation(args.request_id, answer == "APPROVE", "cli_prompt")
                )
            )
    except (Refused, KeyboardInterrupt, EOFError) as e:
        print(str(e) if isinstance(e, Refused) else "cancelled", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
