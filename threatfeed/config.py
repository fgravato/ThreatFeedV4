"""Configuration: API endpoints, timeouts, and API key resolution."""

import os
import stat
import sys
from pathlib import Path
from typing import Optional

BASE_URL = "https://api.lookout.com/mgmt/threat-feeds/api/v1"
TOKEN_URL = "https://api.lookout.com/oauth2/token"

# (connect, read) timeouts in seconds — no request may hang forever.
DEFAULT_TIMEOUT = (10, 60)

API_KEY_ENV_VAR = "LOOKOUT_API_KEY"
API_KEY_FILENAME = "api_key.txt"


def _warn_insecure_permissions(path: Path) -> None:
    """Warn if the API key file is readable by group/other (POSIX only)."""
    try:
        mode = path.stat().st_mode
    except OSError:
        return
    if mode & (stat.S_IRGRP | stat.S_IROTH):
        print(
            f"warning: {path} is readable by group/other — consider `chmod 600 {path}`",
            file=sys.stderr,
        )


def load_api_key() -> Optional[str]:
    """Resolve the API key.

    Resolution order:
      1. LOOKOUT_API_KEY environment variable
      2. api_key.txt next to the project root (parent of this package)
      3. api_key.txt in the current working directory
    """
    key = os.environ.get(API_KEY_ENV_VAR, "").strip()
    if key:
        return key

    candidates = [
        Path(__file__).resolve().parent.parent / API_KEY_FILENAME,
        Path.cwd() / API_KEY_FILENAME,
    ]
    for path in candidates:
        try:
            key = path.read_text().strip()
        except FileNotFoundError:
            continue
        except OSError:
            continue
        if key:
            _warn_insecure_permissions(path)
            return key

    return None


def api_key_hint() -> str:
    return (
        "No API key found. Set the LOOKOUT_API_KEY environment variable or create "
        f"'{API_KEY_FILENAME}' in the project directory containing your Lookout API key."
    )
