"""Command-line entry point for the fail-closed Warden Gateway."""

from __future__ import annotations

import argparse
import sys

from warden_guard.aio import AsyncWardenClient
from warden_guard.client import DEFAULT_BASE_URL
from warden_guard.proxy import WardenReverseProxy


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="warden-gateway",
        description="Run a fail-closed Warden reverse proxy before an HTTP agent.",
    )
    parser.add_argument("--upstream", required=True, help="HTTP(S) origin to protect")
    parser.add_argument(
        "--mode",
        choices=("local", "hosted"),
        default="local",
        help="local in-process scanning or a protected hosted /scan endpoint",
    )
    parser.add_argument(
        "--warden-url",
        default=DEFAULT_BASE_URL,
        help="hosted Warden origin; used only with --mode hosted",
    )
    parser.add_argument("--listen", default="0.0.0.0", help="gateway listen address")
    parser.add_argument("--port", type=int, default=8787, help="gateway listen port")
    parser.add_argument("--max-body-bytes", type=int, default=100_000)
    args = parser.parse_args(argv)

    if not 1 <= args.port <= 65_535:
        parser.error("port must be between 1 and 65535")
    if args.max_body_bytes < 1:
        parser.error("max-body-bytes must be positive")
    if args.mode == "local" and args.warden_url != DEFAULT_BASE_URL:
        parser.error("--warden-url applies only to --mode hosted")

    try:
        import uvicorn
    except ImportError:
        parser.error("warden-gateway requires the 'proxy' package extra")

    client = AsyncWardenClient(
        base_url=args.warden_url,
        paid=args.mode == "hosted",
        local=args.mode == "local",
        fail_open=False,
    )
    app = WardenReverseProxy(
        args.upstream,
        client=client,
        max_body_bytes=args.max_body_bytes,
    )
    uvicorn.run(app, host=args.listen, port=args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
