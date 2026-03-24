"""CLI entry point: python -m fabric [options] <handle> [<handle> ...]"""

import sys

import libveritas as lv

from .seeds import DEFAULT_SEEDS
from .client import Fabric


def main():
    args = sys.argv[1:]
    handles: list[str] = []
    seeds: list[str] = []
    trust_id = ""
    dev_mode = False

    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--seeds":
            i += 1
            if i >= len(args):
                _exit_usage("--seeds requires a value")
            seeds = args[i].split(",")
        elif arg == "--trust-id":
            i += 1
            if i >= len(args):
                _exit_usage("--trust-id requires a value")
            trust_id = args[i]
        elif arg == "--dev-mode":
            dev_mode = True
        elif arg in ("--help", "-h"):
            _print_usage()
            sys.exit(0)
        elif arg.startswith("-"):
            _exit_usage(f"unknown option: {arg}")
        else:
            handles.append(arg)
        i += 1

    if not handles:
        _exit_usage("no handles specified")

    if not seeds:
        seeds = list(DEFAULT_SEEDS)

    f = Fabric(
        seeds=seeds,
        dev_mode=dev_mode,
    )

    try:
        if trust_id:
            f.trust(trust_id)
        batch = f.resolve_all(handles)
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)

    for handle in handles:
        z = next((z for z in batch.zones if z.handle == handle), None)
        if z is None:
            print(f"{handle}: not found", file=sys.stderr)
            continue
        try:
            print(lv.zone_to_json(z))
        except Exception as e:
            print(f"{handle}: {e}", file=sys.stderr)


def _print_usage():
    print("""Usage: fabric [options] <handle> [<handle> ...]

Resolve handles via the certrelay network.

Options:
  --seeds <url,url,...>      Seed relay URLs (comma-separated)
  --trust-id <hex>           Trust ID for verification (hex-encoded)
  --dev-mode                 Enable dev mode (skip finality checks)
  -h, --help                 Show this help""")


def _exit_usage(msg: str):
    print(f"error: {msg}", file=sys.stderr)
    _print_usage()
    sys.exit(1)


if __name__ == "__main__":
    main()
