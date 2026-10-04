"""Small terminal presentation helpers, with plain output for redirected logs."""

import os
import sys


def styled(text: str, color: str, stream=None) -> str:
    stream = stream if stream is not None else sys.stdout
    if stream.isatty() and "NO_COLOR" not in os.environ and os.environ.get("TERM") != "dumb":
        return f"\033[{color}m{text}\033[0m"
    return text


def heading(text: str) -> None:
    print("\n" + styled(f"› {text}", "1;36"), flush=True)


def info(text: str) -> None:
    print("\n".join("  " + line for line in text.splitlines()), flush=True)


def success(text: str) -> None:
    print("  " + styled(f"✓ {text}", "32"), flush=True)


def warning(text: str) -> None:
    print("  " + styled(f"! {text}", "33"), flush=True)


def error(text: str) -> None:
    print("  " + styled(f"× {text}", "31", sys.stderr), file=sys.stderr, flush=True)


def waiting(text: str) -> None:
    print("  " + styled(f"… {text}", "33"), flush=True)


def prompt(text: str) -> str:
    return styled("  ? " + text, "36")


def resources(cpus: int, memory: int, keep_cpus: int, keep_mb: int) -> None:
    print(flush=True)
    info(f"{'Resources':<22} {'CPU threads':>12} {'RAM (GB)':>12}")
    for label, threads, mb in (("Total budget", cpus, memory), ("Host reserve", keep_cpus, keep_mb),
                                ("Available to cluster", cpus - keep_cpus, memory - keep_mb)):
        row = f"{label:<22} {threads:>12} {mb / 1024:>12.1f}"
        info(styled(row, "1") if label == "Available to cluster" else row)
    print(flush=True)
