# Threat Feed Management System

Manage Lookout threat feeds via the Lookout REST API. Provides an interactive
menu, modern CLI subcommands, and backward-compatible legacy flags for
automation and scripting.

## Features

- Browse feeds in a numbered table — metadata for all feeds fetched in parallel
- View, search, add, remove, and bulk-update domains within a feed
- Update feed content from a remote URL (OVERWRITE or INCREMENTAL)
- **Dry-run diff previews** — see `+added / −removed / =unchanged` before any change
- **Export domains to a file** — backups that round-trip with `add --file`
- **Domain search** — substring matching from CLI or `/pattern` in the viewer
- **JSON output** — `--json` for scripting and piping into `jq`
- Delete feeds with typed confirmation
- Batch domain operations: multiple domains inline or from a file
- Resilient HTTP: connection pooling, retries with backoff on 429/5xx,
  request timeouts, and automatic bearer-token refresh on expiry
- Full CLI automation support with consistent exit codes

## Prerequisites

- Python 3.9+
- `pip install -r requirements.txt` (or `pip install .` to get the `threatfeed` command)

For development (tests): `pip install -r requirements-dev.txt`

## Setup

Provide your Lookout API key in one of two ways:

```bash
# Option 1: environment variable
export LOOKOUT_API_KEY="your-api-key-here"

# Option 2: a file in the project directory (keep it private!)
echo "your-api-key-here" > api_key.txt
chmod 600 api_key.txt
```

## Interactive Mode

```bash
threatfeed
# or: python improved_threat_feed_management.py
```

**Navigation:** `b` goes back one level, `q` quits from anywhere.

**Menu flow:**

```
Main Menu
├── 1. Browse and manage feeds
│       Table of all feeds. Enter a number to open a feed.
│       Inside a feed:
│           1. View / search domains  (n/p to page, /text to filter)
│           2. Add domain(s)          — space-separated list or file path
│           3. Remove domain(s)       — diff preview + confirmation
│           4. Update from URL        — diff preview; OVERWRITE confirms
│           5. Export domains to file
│           6. Delete this feed       (requires typing 'yes')
└── 2. Create a new feed
```

## CLI Reference

```bash
threatfeed [--json] COMMAND ...
```

| Command | Description |
|---|---|
| `list` | List all feeds as a table |
| `create TITLE DESC` | Create a new CSV feed |
| `view FEED_ID` | Print feed metadata as JSON |
| `delete FEED_ID [-y]` | Delete a feed (prompts unless `-y`) |
| `add FEED_ID [DOMAIN ...] [--file F] [--dry-run]` | Add domains |
| `remove FEED_ID [DOMAIN ...] [--file F] [--dry-run] [-y]` | Remove domains |
| `update FEED_ID URL [--upload-type M] [--dry-run] [-y] [--no-verify-ssl]` | Update feed content from a URL |
| `export FEED_ID [-o FILE]` | Export domains to a file or stdout |
| `search FEED_ID PATTERN` | Find domains containing PATTERN |

Global flags: `--json` (machine output), `--verbose` (debug logging),
`--version`. Exit code is `0` on success, `1` on any error.

### Examples

```bash
# List all feeds
threatfeed list

# Create a feed (type is always CSV)
threatfeed create "My Feed Title" "Phishing domains for ACME"

# Add multiple domains at once
threatfeed add FEED_ID evil.com phishing.net malware.org

# Add domains from a file
threatfeed add FEED_ID --file domains.txt

# Preview what an update would change (no mutation)
threatfeed update FEED_ID https://example.com/feed.txt --dry-run

# Update feed from a URL, skipping the confirmation prompt
threatfeed update FEED_ID https://example.com/feed.txt -y

# Update incrementally (add new domains only)
threatfeed update FEED_ID https://example.com/feed.txt --upload-type INCREMENTAL

# Back up a feed, then restore it later
threatfeed export FEED_ID -o backup.txt
threatfeed add FEED_ID --file backup.txt

# Find domains in a large feed
threatfeed search FEED_ID evil

# Scripting with jq
threatfeed --json list | jq '.[].title'
```

### Legacy flags

All pre-2.0 flags remain supported and behave as before (no confirmation
prompts, so existing scripts keep working):

```bash
threatfeed --list-feeds
threatfeed --create-feed "Title" "Description"
threatfeed --view-feed FEED_ID
threatfeed --add-domain FEED_ID d1.com d2.com
threatfeed --remove-domain FEED_ID d1.com
threatfeed --add-domains-file FEED_ID domains.txt
threatfeed --remove-domains-file FEED_ID domains.txt
threatfeed --update-feed FEED_ID URL [--upload-type INCREMENTAL|OVERWRITE] [--no-verify-ssl]
threatfeed --delete-feed FEED_ID
```

## Domain Files

Domain files used with `--file`, `export -o`, or interactive prompts:

- One domain per line
- Lines starting with `#` are comments; blank lines are skipped
- Entries are normalized (lowercased, trailing dots stripped) and deduplicated
- Invalid domains are skipped with a warning

```
# Phishing domains — updated 2026-07
evil.com
phishing.net
# malware.org  (disabled)
bad-actor.io
```

## Upload Modes

| Mode | Behaviour |
|---|---|
| `OVERWRITE` | Replaces **all** domains in the feed with the new list |
| `INCREMENTAL` | Merges changes — adds new domains, removes deleted ones |

## Project Layout

```
threatfeed/
├── config.py        # API key resolution, endpoints, timeouts
├── domains.py       # validation, normalization, CSV, diffs
├── client.py        # ThreatFeedClient: session, retries, token refresh
├── output.py        # colors (TTY-aware), tables, JSON, diff rendering
├── cli.py           # subcommands + legacy flags, exit codes
└── interactive.py   # menu system
tests/               # pytest suite (HTTP fully mocked)
improved_threat_feed_management.py  # backward-compatible shim
```

## Development

```bash
python3 -m venv .venv
.venv/bin/pip install -e . -r requirements-dev.txt
.venv/bin/pytest
```

## Troubleshooting

- **API key error** — set `LOOKOUT_API_KEY` or create `api_key.txt`; the key
  file is resolved relative to the project directory, not your CWD.
- **SSL errors on URL update** — use `--no-verify-ssl` if the source URL uses
  a self-signed certificate.
- **Domains skipped** — the validator rejects IP addresses, bare hostnames,
  and entries with spaces or special characters. Check the warnings.
- **Colors in piped output** — colors auto-disable when stdout is not a TTY
  (and honor `NO_COLOR`), so piping into files/`jq` stays clean.

## Author

Frank Gravato (Lookout-SE)
