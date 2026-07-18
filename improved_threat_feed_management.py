#!/usr/bin/env python3
"""Backward-compatible entry point for the Threat Feed Management System.

The implementation now lives in the 'threatfeed' package. This shim keeps
every previously documented invocation working:

    python improved_threat_feed_management.py                # interactive menu
    python improved_threat_feed_management.py --list-feeds   # legacy flags
    python improved_threat_feed_management.py list           # subcommands

Prefer the installed console script instead:  threatfeed ...
"""

import sys

from threatfeed.cli import main

if __name__ == "__main__":
    sys.exit(main())
