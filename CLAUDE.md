# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ThreatFeedV4 is a Python CLI tool for managing Lookout threat feeds (collections of malicious domains) via the Lookout REST API. It supports both an interactive menu-driven mode and non-interactive CLI automation.

## Setup

1. Install dependencies: `pip install -r requirements.txt`
2. Create `api_key.txt` in the project root containing the Lookout API key (not committed to git)

## Running the Script

**Interactive menu mode:**
```bash
python improved_threat_feed_management.py
```

**CLI automation mode:**
```bash
python improved_threat_feed_management.py --list-feeds
python improved_threat_feed_management.py --create-feed CSV "Title" "Description"
python improved_threat_feed_management.py --view-feed <feed-id>
python improved_threat_feed_management.py --update-feed <feed-id> <url> [--upload-type OVERWRITE|INCREMENTAL]
python improved_threat_feed_management.py --delete-feed <feed-id>
python improved_threat_feed_management.py --add-domain <feed-id> <domain>
python improved_threat_feed_management.py --remove-domain <feed-id> <domain>
```

There are no tests in this project.

## Architecture

The entire application lives in a single file: `improved_threat_feed_management.py`.

**Authentication flow:** `load_api_key()` reads `api_key.txt` → `get_bearer()` exchanges it for an OAuth2 bearer token via `POST https://api.lookout.com/oauth2/token`. The bearer token is passed to every subsequent API call.

**API base URL:** `https://api.lookout.com/mgmt/threat-feeds/api/v1`

**Dual-mode dispatch in `main()`:** If CLI args are present, functions are called directly and the script exits. Otherwise, the interactive menu loop starts using a `MenuContext` dataclass to track breadcrumb navigation state (current menu level, active feed ID/name).

**Domain upload mechanics:** Both `add_domain_to_feed()` and `remove_domain_from_feed()` work by fetching the current domain list, modifying it in memory, then re-uploading. `upload_threat_domains()` uses manually constructed multipart/form-data (no library). Upload type `INCREMENTAL` merges; `OVERWRITE` replaces entirely.

**Pagination:** `view_domains()` pages through domains 20 at a time with `n`/`p` navigation.

## Runtime Files

- `api_key.txt` — required, contains the Lookout API key (must be created manually, not in repo)
- `feed_id.txt` — auto-created, stores the most recently created feed's ID
