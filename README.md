# Threat Feed Management System

Manage Lookout threat feeds via the Lookout REST API. Supports an interactive menu and non-interactive CLI for automation and scripting.

## Features

- Browse feeds in a numbered table — pick one to manage it
- View, add, remove, and bulk-update domains within a feed
- Update feed content from a remote URL (OVERWRITE or INCREMENTAL)
- Delete feeds with typed confirmation
- Batch domain operations: multiple domains inline or from a file
- Paginated domain viewer with forward/back navigation
- Color-coded terminal interface with breadcrumb navigation
- Full CLI automation support with proper exit codes

## Prerequisites

- Python 3.x
- `pip install -r requirements.txt`

## Setup

Create an `api_key.txt` file in the project directory containing your Lookout API key:

```bash
echo "your-api-key-here" > api_key.txt
```

## Interactive Mode

```bash
python improved_threat_feed_management.py
```

**Navigation:** `b` goes back one level, `q` quits from anywhere.

**Menu flow:**

```
Main Menu
├── 1. Browse and manage feeds
│       Shows a table of all feeds. Enter a number to open a feed.
│       Inside a feed:
│           1. View domains (paginated, n/p to page)
│           2. Add domain(s)   — space-separated list or file path
│           3. Remove domain(s) — space-separated list or file path
│           4. Update from URL
│           5. Delete this feed  (requires typing 'yes')
└── 2. Create a new feed
```

## CLI Reference

```bash
python improved_threat_feed_management.py [OPTIONS]
```

| Flag | Description |
|---|---|
| `--list-feeds` | Print all feeds as a table |
| `--create-feed TITLE DESC` | Create a new CSV feed |
| `--view-feed FEED_ID` | Print feed metadata as JSON |
| `--update-feed FEED_ID URL` | Download and upload domains from a URL |
| `--upload-type INCREMENTAL\|OVERWRITE` | Upload mode for `--update-feed` (default: OVERWRITE) |
| `--delete-feed FEED_ID` | Delete a feed |
| `--add-domain FEED_ID d1 [d2 ...]` | Add one or more domains |
| `--remove-domain FEED_ID d1 [d2 ...]` | Remove one or more domains |
| `--add-domains-file FEED_ID FILE` | Add all domains from a file |
| `--remove-domains-file FEED_ID FILE` | Remove all domains from a file |
| `--no-verify-ssl` | Disable SSL verification for URL downloads |

Exit code is `1` on any error.

### Examples

```bash
# List all feeds
python improved_threat_feed_management.py --list-feeds

# Create a feed (type is always CSV)
python improved_threat_feed_management.py --create-feed "My Feed" "Phishing domains for ACME"

# Add multiple domains at once
python improved_threat_feed_management.py --add-domain FEED_ID evil.com phishing.net malware.org

# Add domains from a file
python improved_threat_feed_management.py --add-domains-file FEED_ID domains.txt

# Remove domains from a file
python improved_threat_feed_management.py --remove-domains-file FEED_ID stale_domains.txt

# Update feed from a URL (replace all)
python improved_threat_feed_management.py --update-feed FEED_ID https://example.com/feed.txt

# Update feed incrementally (add new domains only)
python improved_threat_feed_management.py --update-feed FEED_ID https://example.com/feed.txt --upload-type INCREMENTAL

# Delete a feed
python improved_threat_feed_management.py --delete-feed FEED_ID
```

## Domain Files

Domain files used with `--add-domains-file`, `--remove-domains-file`, or typed into interactive add/remove prompts follow this format:

- One domain per line
- Lines starting with `#` are treated as comments and skipped
- Blank lines are skipped
- Invalid domains are skipped with a warning

```
# Phishing domains — updated 2026-04
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

## Troubleshooting

- **API key error** — ensure `api_key.txt` exists in the script directory and contains a valid key.
- **SSL errors on URL update** — use `--no-verify-ssl` if the source URL uses a self-signed certificate.
- **Domains skipped** — the domain validator rejects IP addresses, bare hostnames, and entries with spaces or special characters. Check the logged warnings.

## Author

Frank Gravato (Lookout-SE)
