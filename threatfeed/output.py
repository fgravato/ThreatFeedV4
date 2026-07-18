"""Terminal output helpers: TTY-aware colors, tables, and JSON printing."""

import json
import os
import shutil
import sys
from typing import Any, Sequence


class Colors:
    HEADER = "\033[95m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"


def _detect_colors() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


_enabled = _detect_colors()


def set_colors_enabled(enabled: bool) -> None:
    global _enabled
    _enabled = enabled


def colorize(text: str, *codes: str) -> str:
    if not _enabled or not codes:
        return text
    return "".join(codes) + text + Colors.ENDC


# ── CLI status messages ───────────────────────────────────────────────────────

def ok(msg: str) -> None:
    print(colorize(msg, Colors.GREEN))


def info(msg: str) -> None:
    print(colorize(msg, Colors.YELLOW))


def err(msg: str) -> None:
    print(colorize(f"error: {msg}", Colors.RED), file=sys.stderr)


# ── Structured output ─────────────────────────────────────────────────────────

def print_json(data: Any) -> None:
    print(json.dumps(data, indent=2))


def print_table(headers: Sequence[str], rows: Sequence[Sequence[str]]) -> None:
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    print(colorize(fmt.format(*headers), Colors.BOLD))
    print(fmt.format(*("-" * w for w in widths)))
    for row in rows:
        print(fmt.format(*row))


def terminal_width() -> int:
    return shutil.get_terminal_size().columns


def divider(char: str = "=") -> None:
    print(char * terminal_width())
