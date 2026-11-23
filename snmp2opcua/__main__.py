"""Entry point:  python -m snmp2opcua -c config.yaml"""
from __future__ import annotations

import argparse
import asyncio
import logging
import sys

from .config import load_config
from .gateway import Gateway


async def _run(cfg: dict) -> None:
    # Build the gateway inside the running loop (asyncio primitives bind to it on Python 3.9)
    await Gateway(cfg).run()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="snmp2opcua", description="Receive SNMP traps and publish them over OPC UA")
    ap.add_argument("-c", "--config", default="config.yaml", help="path to YAML config (default: config.yaml)")
    ap.add_argument("--log-level", help="override logging level (DEBUG, INFO, WARNING...)")
    ap.add_argument("--port", type=int, help="override snmp.listen_port")
    ap.add_argument("--gui", action="store_true", help="open the desktop window instead of running headless")
    args = ap.parse_args(argv)
    if args.gui:
        from .gui import main as gui_main
        return gui_main(["-c", args.config])

    try:
        cfg = load_config(args.config)
    except FileNotFoundError:
        print(f"Config file not found: {args.config}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"Invalid config: {exc}", file=sys.stderr)
        return 2
    if args.port:          # one listener on this port instead of the configured network interfaces
        cfg["snmp"]["listen_port"] = args.port
        cfg["snmp"]["network_interfaces"] = []

    level = (args.log_level or cfg["logging"].get("level", "INFO")).upper()
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    if level != "DEBUG":
        logging.getLogger("asyncua").setLevel(logging.WARNING)

    try:
        asyncio.run(_run(cfg))
    except KeyboardInterrupt:
        pass
    except OSError:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
