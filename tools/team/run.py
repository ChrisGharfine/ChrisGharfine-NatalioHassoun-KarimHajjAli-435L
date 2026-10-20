"""Load a private dotenv file and execute one owner's native command.

Usage: python tools/team/run.py --env-file .env.team karim worker.py --flush
       python tools/team/run.py chris -m services.chris_support.audit_worker --once
"""
import argparse
import os
from pathlib import Path
import subprocess
import sys
from dotenv import load_dotenv


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", default=".env.team")
    parser.add_argument("owner", choices=("natalio", "chris", "karim"))
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if not args.command:
        parser.error("Supply the owner's Python command after its name")
    root = Path(__file__).resolve().parents[2]
    path = Path(args.env_file).resolve()
    if not path.is_file():
        parser.error("Private environment file not found; supply --env-file")
    load_dotenv(path, override=True)
    return subprocess.call([sys.executable, *args.command], cwd=root, env=os.environ.copy())


if __name__ == "__main__":
    raise SystemExit(main())
