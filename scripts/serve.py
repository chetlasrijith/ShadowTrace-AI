"""Serve the ShadowTrace simulation UI. One command:

    python scripts/serve.py [--port 8137] [--no-browser]

Localhost only. Detection, rewriting, and answering all stay on this
machine; the page it serves is a window onto the local pipeline.
"""

from __future__ import annotations

import argparse
import sys
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "server"))

import uvicorn  # noqa: E402


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="ShadowTrace simulation server")
    ap.add_argument("--port", type=int, default=8137)
    ap.add_argument("--no-browser", action="store_true")
    args = ap.parse_args(argv)

    url = f"http://127.0.0.1:{args.port}"
    print(f"ShadowTrace simulation at {url}  (localhost only, Ctrl+C to stop)")
    if not args.no_browser:
        webbrowser.open(url)
    uvicorn.run("app:app", host="127.0.0.1", port=args.port,
                app_dir=str(ROOT / "server"), log_level="warning")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
