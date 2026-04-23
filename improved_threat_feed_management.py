#!/usr/bin/env python3
"""
Threat Feed Management Script

Manages Lookout threat feeds via the Lookout REST API.
Supports interactive menu mode and non-interactive CLI automation.

Usage:
    Interactive: python improved_threat_feed_management.py
    CLI:         python improved_threat_feed_management.py --help

Requirements:
    Python 3.x, requests library

Configuration:
    Create 'api_key.txt' in the script directory with your Lookout API key.

Author:
    Frank Gravato (Lookout-SE)
"""

import requests
import json
import urllib3
import sys
import os
import tempfile
import uuid
import re
import logging
from urllib.parse import urlparse
from typing import List, Optional, Dict, Tuple
import argparse
from dataclasses import dataclass, field
import shutil


# ── Terminal colors ───────────────────────────────────────────────────────────

class Colors:
    HEADER    = '\033[95m'
    BLUE      = '\033[94m'
    CYAN      = '\033[96m'
    GREEN     = '\033[92m'
    YELLOW    = '\033[93m'
    RED       = '\033[91m'
    ENDC      = '\033[0m'
    BOLD      = '\033[1m'


# ── Menu state ────────────────────────────────────────────────────────────────

@dataclass
class MenuContext:
    current_feed_id:    Optional[str] = None
    current_feed_title: Optional[str] = None
    breadcrumb: List[str] = field(default_factory=lambda: ["Main Menu"])

    def update_feed(self, feed_id: Optional[str], title: Optional[str]) -> None:
        self.current_feed_id    = feed_id
        self.current_feed_title = title

    def push(self, name: str) -> None:
        self.breadcrumb.append(name)

    def pop(self) -> None:
        if len(self.breadcrumb) > 1:
            self.breadcrumb.pop()

    def reset(self) -> None:
        self.breadcrumb         = ["Main Menu"]
        self.current_feed_id    = None
        self.current_feed_title = None


# ── Logging ───────────────────────────────────────────────────────────────────

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


# ── Constants ─────────────────────────────────────────────────────────────────

BASE_URL       = "https://api.lookout.com/mgmt/threat-feeds/api/v1"
API_KEY_FILE   = "api_key.txt"
DOMAIN_PATTERN = re.compile(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')
_BASE_HEADERS  = {"Content-Type": "application/json", "Accept": "application/json"}


# ── CLI argument parsing ──────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Threat Feed Management System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  List all feeds:
    %(prog)s --list-feeds

  Create a feed:
    %(prog)s --create-feed "My Feed Title" "Feed description here"

  View a feed:
    %(prog)s --view-feed FEED_ID

  Add one or more domains:
    %(prog)s --add-domain FEED_ID evil.com phishing.net malware.org

  Remove one or more domains:
    %(prog)s --remove-domain FEED_ID evil.com phishing.net

  Add domains from a file (one per line, # comments ignored):
    %(prog)s --add-domains-file FEED_ID domains.txt

  Remove domains from a file:
    %(prog)s --remove-domains-file FEED_ID domains.txt

  Update feed from a URL (OVERWRITE by default):
    %(prog)s --update-feed FEED_ID https://example.com/feed.txt
    %(prog)s --update-feed FEED_ID https://example.com/feed.txt --upload-type INCREMENTAL

  Delete a feed:
    %(prog)s --delete-feed FEED_ID
""",
    )
    parser.add_argument("--list-feeds", action="store_true",
                        help="List all feeds as a table")
    parser.add_argument("--create-feed", nargs=2, metavar=("TITLE", "DESCRIPTION"),
                        help="Create a new CSV feed")
    parser.add_argument("--view-feed", metavar="FEED_ID",
                        help="Print feed metadata as JSON")
    parser.add_argument("--update-feed", nargs=2, metavar=("FEED_ID", "SOURCE_URL"),
                        help="Update feed content from a URL")
    parser.add_argument("--upload-type", choices=["INCREMENTAL", "OVERWRITE"], default="OVERWRITE",
                        help="Upload type for --update-feed (default: OVERWRITE)")
    parser.add_argument("--delete-feed", metavar="FEED_ID",
                        help="Delete a feed")
    parser.add_argument("--add-domain", nargs="+", metavar=("FEED_ID", "DOMAIN"),
                        help="Add one or more domains: --add-domain FEED_ID d1.com d2.com ...")
    parser.add_argument("--remove-domain", nargs="+", metavar=("FEED_ID", "DOMAIN"),
                        help="Remove one or more domains: --remove-domain FEED_ID d1.com d2.com ...")
    parser.add_argument("--add-domains-file", nargs=2, metavar=("FEED_ID", "FILE"),
                        help="Add all domains listed in FILE (one per line)")
    parser.add_argument("--remove-domains-file", nargs=2, metavar=("FEED_ID", "FILE"),
                        help="Remove all domains listed in FILE (one per line)")
    parser.add_argument("--no-verify-ssl", action="store_true",
                        help="Disable SSL certificate verification for feed content downloads")
    return parser.parse_args()


# ── Authentication ────────────────────────────────────────────────────────────

def load_api_key() -> Optional[str]:
    try:
        with open(API_KEY_FILE) as f:
            return f.read().strip()
    except FileNotFoundError:
        logger.error(f"API key file '{API_KEY_FILE}' not found.")
        return None


def get_bearer(api_key: str) -> Optional[str]:
    try:
        response = requests.post(
            "https://api.lookout.com/oauth2/token",
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            data={"grant_type": "client_credentials"},
        )
        response.raise_for_status()
        token = response.json().get("access_token")
        if not token:
            logger.error("Access token not found in response.")
        return token
    except requests.exceptions.RequestException as e:
        logger.error(f"Token retrieval failed: {e}")
        return None


# ── API helpers ───────────────────────────────────────────────────────────────

def _headers(access_token: str) -> Dict[str, str]:
    h = _BASE_HEADERS.copy()
    h["Authorization"] = f"Bearer {access_token}"
    return h


def get_feed_guids(access_token: str) -> Optional[List[str]]:
    try:
        r = requests.get(f"{BASE_URL}/threat-feeds", headers=_headers(access_token))
        r.raise_for_status()
        return r.json()
    except requests.exceptions.RequestException as e:
        logger.error(f"Error retrieving feeds: {e}")
        return None


def get_feed_metadata(feed_id: str, access_token: str) -> Optional[Dict]:
    try:
        r = requests.get(f"{BASE_URL}/threat-feeds/{feed_id}", headers=_headers(access_token))
        r.raise_for_status()
        return r.json()
    except requests.exceptions.RequestException as e:
        logger.error(f"Error retrieving feed metadata: {e}")
        return None


def create_threat_feed(title: str, description: str, access_token: str) -> Optional[str]:
    if len(title) < 8 or len(title) > 255:
        logger.error("Title must be 8–255 characters.")
        return None
    if len(description) < 8 or len(description) > 255:
        logger.error("Description must be 8–255 characters.")
        return None
    try:
        r = requests.post(
            f"{BASE_URL}/threat-feeds",
            headers=_headers(access_token),
            json={"feedType": "CSV", "title": title, "description": description},
        )
        r.raise_for_status()
        feed_id = r.json()["feedId"]
        logger.info(f"Feed created: {feed_id}")
        return feed_id
    except requests.exceptions.HTTPError as e:
        detail = ""
        try:
            detail = e.response.json().get("detail", "")
        except Exception:
            pass
        if "max allowed feed limit" in detail:
            logger.error("Tenant has reached the maximum allowed feed limit.")
        else:
            logger.error(f"Error creating feed: {e.response.status_code} – {detail or e}")
        return None
    except requests.exceptions.RequestException as e:
        logger.error(f"Error creating feed: {e}")
        return None


def delete_threat_feed(feed_id: str, access_token: str) -> bool:
    try:
        r = requests.delete(f"{BASE_URL}/threat-feeds/{feed_id}", headers=_headers(access_token))
        r.raise_for_status()
        logger.info("Feed deleted.")
        return True
    except requests.exceptions.RequestException as e:
        logger.error(f"Error deleting feed: {e}")
        return False


def get_threat_domains(feed_id: str, access_token: str) -> Optional[List[str]]:
    h = _headers(access_token)
    h["Accept"] = "text/csv"
    try:
        r = requests.get(f"{BASE_URL}/threat-feeds/{feed_id}/elements", headers=h)
        r.raise_for_status()
        lines = r.text.strip().split("\n")
        return [line.rstrip('\r') for line in lines[1:] if line.strip()]
    except requests.exceptions.RequestException as e:
        logger.error(f"Error retrieving domains: {e}")
        return None


def upload_threat_domains(
    feed_id: str,
    domains: List[Tuple[str, Optional[str]]],
    access_token: str,
    upload_type: str = "INCREMENTAL",
) -> bool:
    """Upload domains as a multipart CSV. Returns True on success."""
    url      = f"{BASE_URL}/threat-feeds/{feed_id}/elements?uploadType={upload_type}"
    boundary = str(uuid.uuid4())
    h        = _headers(access_token)
    h["Content-Type"] = f"multipart/form-data; boundary={boundary}"
    del h["Accept"]

    temp_file_path = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as tmp:
            if upload_type == "INCREMENTAL":
                tmp.write("domain,action\n")
                for domain, action in domains:
                    tmp.write(f"{domain},{action}\n")
            else:
                tmp.write("domain\n")
                for domain, _ in domains:
                    tmp.write(f"{domain}\n")
            temp_file_path = tmp.name

        with open(temp_file_path, "rb") as f:
            csv_content = f.read().decode()

        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="domains.csv"\r\n'
            f"Content-Type: text/csv\r\n\r\n"
            f"{csv_content}\r\n"
            f"--{boundary}--\r\n"
        )
        r = requests.post(url, headers=h, data=body.encode())
        r.raise_for_status()
        logger.info(f"Uploaded {len(domains)} domain(s) ({upload_type}).")
        return True
    except requests.exceptions.RequestException as e:
        logger.error(f"Error uploading domains: {e}")
        return False
    finally:
        if temp_file_path:
            os.unlink(temp_file_path)


def update_feed_content(
    feed_id: str,
    source_url: str,
    access_token: str,
    upload_type: str = "OVERWRITE",
    verify_ssl: bool = True,
) -> bool:
    """Download domains from source_url and upload to the feed. Returns True on success."""
    parsed = urlparse(source_url)
    if parsed.scheme not in ('http', 'https'):
        logger.error(f"Invalid URL scheme '{parsed.scheme}'. Only http/https allowed.")
        return False

    if not verify_ssl:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    try:
        r = requests.get(source_url, verify=verify_ssl)
        r.raise_for_status()
        content = r.content.decode("utf-8")
    except requests.exceptions.RequestException as e:
        status = getattr(getattr(e, 'response', None), 'status_code', None)
        logger.error(f"Error downloading content (HTTP {status}): {e}" if status else f"Error downloading content: {e}")
        return False

    loose = re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b')
    domains: List[Tuple[str, Optional[str]]] = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if not line.startswith(("http://", "https://")):
            line = "https://" + line
        netloc = urlparse(line).netloc
        if netloc and loose.match(netloc):
            domains.append((netloc, "add" if upload_type == "INCREMENTAL" else None))

    if not domains:
        logger.warning("No valid domains found in source content.")
        return False

    return upload_threat_domains(feed_id, domains, access_token, upload_type)


# ── Domain file helper ────────────────────────────────────────────────────────

def load_domains_from_file(path: str) -> Optional[List[str]]:
    """Read and validate domains from a file (one per line, # comments ignored)."""
    try:
        with open(path) as f:
            lines = f.readlines()
    except FileNotFoundError:
        logger.error(f"File not found: {path}")
        return None
    except OSError as e:
        logger.error(f"Error reading file: {e}")
        return None

    valid, invalid = [], []
    for raw in lines:
        d = raw.strip()
        if not d or d.startswith('#'):
            continue
        (valid if DOMAIN_PATTERN.match(d) else invalid).append(d)

    if invalid:
        preview = ', '.join(invalid[:5]) + ('...' if len(invalid) > 5 else '')
        logger.warning(f"Skipped {len(invalid)} invalid domain(s): {preview}")

    return valid if valid else None


# ── Display helpers ───────────────────────────────────────────────────────────

def _cols() -> int:
    return shutil.get_terminal_size().columns

def _divider(char: str = "=") -> None:
    print(char * _cols())

def display_header(ctx: MenuContext) -> None:
    print()
    _divider()
    print(f"{Colors.HEADER}{Colors.BOLD}  Threat Feed Management System{Colors.ENDC}")
    print(f"  {Colors.BLUE}{' > '.join(ctx.breadcrumb)}{Colors.ENDC}")
    if ctx.current_feed_title:
        print(f"  {Colors.YELLOW}Feed: {ctx.current_feed_title}{Colors.ENDC}")
    _divider()

def _nav_hint(*extras: str) -> None:
    parts = list(extras) + ["b: back", "q: quit"]
    print(f"\n  {Colors.GREEN}{' | '.join(parts)}{Colors.ENDC}")

def _prompt(msg: str) -> str:
    return input(f"\n  {msg}: ").strip()

def _ok(msg: str)   -> None: print(f"\n  {Colors.GREEN}{msg}{Colors.ENDC}")
def _err(msg: str)  -> None: print(f"\n  {Colors.RED}{msg}{Colors.ENDC}")
def _info(msg: str) -> None: print(f"\n  {Colors.YELLOW}{msg}{Colors.ENDC}")


# ── Interactive navigation helper ─────────────────────────────────────────────

def _is_back(choice: str) -> bool:
    return choice.lower() in ('b', 'h')

def _is_quit(choice: str) -> bool:
    if choice.lower() == 'q':
        print(f"\n  {Colors.GREEN}Goodbye!{Colors.ENDC}")
        return True
    return False


# ── Interactive screens ───────────────────────────────────────────────────────

def browse_feeds(access_token: str, ctx: MenuContext) -> None:
    """Show a numbered feed table; pick a number to open that feed."""
    ctx.push("Feeds")
    while True:
        display_header(ctx)
        guids = get_feed_guids(access_token)

        if not guids:
            _info("No threat feeds found.")
            _nav_hint("r: refresh")
            choice = _prompt("Choice")
            if _is_quit(choice):
                ctx.pop()
                sys.exit(0)
            ctx.pop()
            return

        feed_meta: List[Tuple[str, Dict]] = []
        print(f"\n  {'#':<4} {'Title':<36} {'Domains':>8}  Updated")
        _divider("-")
        for i, guid in enumerate(guids, 1):
            meta = get_feed_metadata(guid, access_token)
            if meta:
                feed_meta.append((guid, meta))
                title   = meta.get('title', guid)[:35]
                count   = meta.get('elementsCount', 0)
                updated = (meta.get('elementsUploadedAt') or 'never')[:10]
                print(f"  {Colors.BOLD}{i:<4}{Colors.ENDC} {Colors.BLUE}{title:<36}{Colors.ENDC} {count:>8}  {updated}")
        _divider("-")

        _nav_hint("number: open feed", "r: refresh")
        choice = _prompt(f"Select feed (1–{len(feed_meta)})")

        if _is_quit(choice):
            ctx.pop()
            sys.exit(0)
        if _is_back(choice):
            ctx.pop()
            return
        if choice.lower() == 'r':
            continue

        try:
            idx = int(choice)
            if 1 <= idx <= len(feed_meta):
                manage_single_feed(feed_meta[idx - 1][0], feed_meta[idx - 1][1], access_token, ctx)
            else:
                _err(f"Enter a number between 1 and {len(feed_meta)}.")
        except ValueError:
            _err("Enter a feed number or shortcut key.")


def manage_single_feed(feed_id: str, initial_meta: Dict, access_token: str, ctx: MenuContext) -> None:
    """All operations on one feed."""
    ctx.update_feed(feed_id, initial_meta.get('title'))
    ctx.push(initial_meta.get('title', feed_id)[:35])

    while True:
        meta = get_feed_metadata(feed_id, access_token)
        if not meta:
            _err("Unable to retrieve feed metadata.")
            ctx.pop()
            ctx.update_feed(None, None)
            return

        ctx.update_feed(feed_id, meta['title'])
        display_header(ctx)

        updated = (meta.get('elementsUploadedAt') or 'never')[:19]
        print(f"\n  {Colors.BLUE}Description:{Colors.ENDC} {meta.get('description', '')}")
        print(f"  {Colors.BLUE}Type:        {Colors.ENDC} {meta.get('feedType', '')}")
        print(f"  {Colors.BLUE}Domains:     {Colors.ENDC} {meta.get('elementsCount', 0)}")
        print(f"  {Colors.BLUE}Updated:     {Colors.ENDC} {updated}")

        print(f"\n  {Colors.BOLD}1.{Colors.ENDC} View domains")
        print(f"  {Colors.BOLD}2.{Colors.ENDC} Add domain(s)")
        print(f"  {Colors.BOLD}3.{Colors.ENDC} Remove domain(s)")
        print(f"  {Colors.BOLD}4.{Colors.ENDC} Update from URL")
        print(f"  {Colors.BOLD}5.{Colors.ENDC} Delete this feed")
        _nav_hint()

        choice = _prompt("Choice")
        if _is_quit(choice):
            sys.exit(0)
        if _is_back(choice):
            ctx.pop()
            ctx.update_feed(None, None)
            return

        if choice == "1":
            view_domains(feed_id, access_token, ctx)
        elif choice == "2":
            _add_domains_interactive(feed_id, access_token, ctx)
        elif choice == "3":
            _remove_domains_interactive(feed_id, access_token, ctx)
        elif choice == "4":
            _update_from_url_interactive(feed_id, access_token, ctx)
        elif choice == "5":
            if _confirm_delete(feed_id, meta.get('title', ''), access_token, ctx):
                return
        else:
            _err("Enter 1–5 or a shortcut key.")


def view_domains(feed_id: str, access_token: str, ctx: MenuContext) -> None:
    ctx.push("Domains")
    domains = get_threat_domains(feed_id, access_token)
    if not domains:
        display_header(ctx)
        _info("No domains in this feed.")
        _prompt("Press Enter to go back")
        ctx.pop()
        return

    page_size   = 20
    page        = 0
    total_pages = max(1, (len(domains) + page_size - 1) // page_size)

    while True:
        display_header(ctx)
        start = page * page_size
        end   = min(start + page_size, len(domains))

        print(f"\n  Domains {start+1}–{end} of {Colors.GREEN}{len(domains)}{Colors.ENDC}"
              f"  (page {Colors.YELLOW}{page+1}{Colors.ENDC}/{total_pages})\n")

        for j, domain in enumerate(domains[start:end]):
            color = Colors.BLUE if j % 2 == 0 else ""
            print(f"  {color}{start+j+1:>4}.  {domain}{Colors.ENDC}")

        _divider("-")
        hints = []
        if page < total_pages - 1:
            hints.append("n: next page")
        if page > 0:
            hints.append("p: prev page")
        _nav_hint(*hints)

        choice = _prompt("Choice").lower()
        if choice == 'n':
            if page < total_pages - 1:
                page += 1
            else:
                _err("Already on the last page.")
        elif choice == 'p':
            if page > 0:
                page -= 1
            else:
                _err("Already on the first page.")
        elif choice in ('b', 'q', 'h', ''):
            break
        else:
            _err("Use n/p to navigate or b to go back.")

    ctx.pop()


def _add_domains_interactive(feed_id: str, access_token: str, ctx: MenuContext) -> None:
    ctx.push("Add Domains")
    display_header(ctx)
    print(f"\n  Enter space-separated domains, or a path to a file (one domain per line).")
    print(f"  Examples:  evil.com phishing.net malware.org")
    print(f"             /path/to/domains.txt")
    raw = _prompt("Domains or file path")
    ctx.pop()

    if not raw or _is_back(raw) or _is_quit(raw):
        return

    domains_list = _parse_domain_input(raw)
    if not domains_list:
        return

    _info(f"Adding {len(domains_list)} domain(s)...")
    if upload_threat_domains(feed_id, [(d, "add") for d in domains_list], access_token, "INCREMENTAL"):
        _ok(f"{len(domains_list)} domain(s) added.")
    else:
        _err("Upload failed — check logs for details.")


def _remove_domains_interactive(feed_id: str, access_token: str, ctx: MenuContext) -> None:
    ctx.push("Remove Domains")
    display_header(ctx)
    print(f"\n  Enter space-separated domains, or a path to a file (one domain per line).")
    raw = _prompt("Domains or file path")
    ctx.pop()

    if not raw or _is_back(raw) or _is_quit(raw):
        return

    domains_list = _parse_domain_input(raw)
    if not domains_list:
        return

    _info(f"Removing {len(domains_list)} domain(s)...")
    if upload_threat_domains(feed_id, [(d, "delete") for d in domains_list], access_token, "INCREMENTAL"):
        _ok(f"{len(domains_list)} domain(s) removed.")
    else:
        _err("Upload failed — check logs for details.")


def _update_from_url_interactive(feed_id: str, access_token: str, ctx: MenuContext) -> None:
    ctx.push("Update from URL")
    display_header(ctx)
    print(f"\n  Download domains from a URL and upload them to this feed.")
    url = _prompt("Source URL (http/https)")
    ctx.pop()

    if not url or _is_back(url):
        return

    print(f"\n  {Colors.BOLD}Upload type:{Colors.ENDC}")
    print(f"  {Colors.BOLD}1.{Colors.ENDC} OVERWRITE    – replace all existing domains")
    print(f"  {Colors.BOLD}2.{Colors.ENDC} INCREMENTAL  – merge new domains into existing ones")
    upload_choice = _prompt("Choice (1/2, default 1)")
    upload_type   = "INCREMENTAL" if upload_choice == "2" else "OVERWRITE"

    _info(f"Downloading and uploading ({upload_type})...")
    if update_feed_content(feed_id, url, access_token, upload_type):
        _ok("Feed content updated.")
    else:
        _err("Update failed — check logs for details.")


def _confirm_delete(feed_id: str, title: str, access_token: str, ctx: MenuContext) -> bool:
    """Returns True if the feed was deleted (caller should exit the feed loop)."""
    ctx.push("Delete Feed")
    display_header(ctx)
    print(f"\n  {Colors.RED}You are about to permanently delete:{Colors.ENDC}")
    print(f"  Title:   {title}")
    print(f"  Feed ID: {feed_id}")
    confirm = _prompt("Type 'yes' to confirm, anything else cancels")
    ctx.pop()

    if confirm.lower() == 'yes':
        if delete_threat_feed(feed_id, access_token):
            _ok(f"Feed '{title}' deleted.")
            return True
        _err("Deletion failed — check logs for details.")
    else:
        _info("Deletion cancelled.")
    return False


def create_new_feed(access_token: str, ctx: MenuContext) -> None:
    ctx.push("Create Feed")
    display_header(ctx)
    print(f"\n  Feed type is CSV (the only supported type).")
    print(f"  Title and description must each be 8–255 characters.\n")
    title       = _prompt("Title")
    description = _prompt("Description")
    ctx.pop()

    if not title or not description:
        _err("Title and description are required.")
        return

    _info("Creating feed...")
    feed_id = create_threat_feed(title, description, access_token)
    if feed_id:
        _ok(f"Feed created.  ID: {Colors.CYAN}{feed_id}{Colors.ENDC}")
    else:
        _err("Feed creation failed — check logs for details.")


def run_interactive(access_token: str) -> None:
    ctx = MenuContext()
    while True:
        display_header(ctx)
        print(f"\n  {Colors.BOLD}1.{Colors.ENDC} Browse and manage feeds")
        print(f"  {Colors.BOLD}2.{Colors.ENDC} Create a new feed")
        print(f"  {Colors.BOLD}3.{Colors.ENDC} Exit")
        _nav_hint()

        choice = _prompt("Choice")
        if _is_quit(choice) or choice == "3":
            if choice == "3":
                print(f"\n  {Colors.GREEN}Goodbye!{Colors.ENDC}")
            break

        if choice == "1":
            browse_feeds(access_token, ctx)
        elif choice == "2":
            create_new_feed(access_token, ctx)
        elif choice not in ('q',):
            _err("Enter 1, 2, or 3.")


# ── Shared input helper ───────────────────────────────────────────────────────

def _parse_domain_input(raw: str) -> Optional[List[str]]:
    """Accept either a file path or space-separated domains. Returns validated list or None."""
    if os.path.exists(raw):
        result = load_domains_from_file(raw)
        if not result:
            _err("No valid domains found in file.")
        return result

    tokens  = raw.split()
    valid   = [t for t in tokens if DOMAIN_PATTERN.match(t)]
    invalid = [t for t in tokens if not DOMAIN_PATTERN.match(t)]
    if invalid:
        _err(f"Skipped invalid: {', '.join(invalid)}")
    if not valid:
        _err("No valid domains to process.")
        return None
    return valid


# ── CLI table output ──────────────────────────────────────────────────────────

def _print_feeds_table(guids: List[str], access_token: str) -> None:
    print(f"\n  {'#':<4} {'Title':<40} {'Domains':>8}  {'Updated':<12}  Feed ID")
    print("  " + "-" * 95)
    for i, guid in enumerate(guids, 1):
        meta = get_feed_metadata(guid, access_token)
        if meta:
            title   = meta.get('title', '')[:39]
            count   = meta.get('elementsCount', 0)
            updated = (meta.get('elementsUploadedAt') or 'never')[:10]
            print(f"  {i:<4} {title:<40} {count:>8}  {updated:<12}  {guid}")
    print()


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    args = parse_args()

    api_key = load_api_key()
    if not api_key:
        sys.exit(1)

    access_token = get_bearer(api_key)
    if not access_token:
        sys.exit(1)

    if args.list_feeds:
        guids = get_feed_guids(access_token)
        if guids:
            _print_feeds_table(guids, access_token)
        else:
            print("No threat feeds found.")

    elif args.create_feed:
        title, description = args.create_feed
        feed_id = create_threat_feed(title, description, access_token)
        if not feed_id:
            sys.exit(1)
        print(f"Feed created: {feed_id}")

    elif args.view_feed:
        meta = get_feed_metadata(args.view_feed, access_token)
        if meta:
            print(json.dumps(meta, indent=2))
        else:
            sys.exit(1)

    elif args.update_feed:
        feed_id, source_url = args.update_feed
        if not update_feed_content(feed_id, source_url, access_token,
                                   args.upload_type, verify_ssl=not args.no_verify_ssl):
            sys.exit(1)

    elif args.delete_feed:
        if not delete_threat_feed(args.delete_feed, access_token):
            sys.exit(1)

    elif args.add_domain:
        if len(args.add_domain) < 2:
            logger.error("Usage: --add-domain FEED_ID domain [domain ...]")
            sys.exit(1)
        feed_id, *raw = args.add_domain
        valid, invalid = _split_valid_domains(raw)
        if invalid:
            logger.warning(f"Skipped invalid: {', '.join(invalid)}")
        if not valid:
            logger.error("No valid domains to add.")
            sys.exit(1)
        if not upload_threat_domains(feed_id, [(d, "add") for d in valid], access_token, "INCREMENTAL"):
            sys.exit(1)
        print(f"Added {len(valid)} domain(s) to {feed_id}.")

    elif args.remove_domain:
        if len(args.remove_domain) < 2:
            logger.error("Usage: --remove-domain FEED_ID domain [domain ...]")
            sys.exit(1)
        feed_id, *raw = args.remove_domain
        valid, invalid = _split_valid_domains(raw)
        if invalid:
            logger.warning(f"Skipped invalid: {', '.join(invalid)}")
        if not valid:
            logger.error("No valid domains to remove.")
            sys.exit(1)
        if not upload_threat_domains(feed_id, [(d, "delete") for d in valid], access_token, "INCREMENTAL"):
            sys.exit(1)
        print(f"Removed {len(valid)} domain(s) from {feed_id}.")

    elif args.add_domains_file:
        feed_id, file_path = args.add_domains_file
        domains = load_domains_from_file(file_path)
        if not domains:
            sys.exit(1)
        if not upload_threat_domains(feed_id, [(d, "add") for d in domains], access_token, "INCREMENTAL"):
            sys.exit(1)
        print(f"Added {len(domains)} domain(s) to {feed_id}.")

    elif args.remove_domains_file:
        feed_id, file_path = args.remove_domains_file
        domains = load_domains_from_file(file_path)
        if not domains:
            sys.exit(1)
        if not upload_threat_domains(feed_id, [(d, "delete") for d in domains], access_token, "INCREMENTAL"):
            sys.exit(1)
        print(f"Removed {len(domains)} domain(s) from {feed_id}.")

    else:
        run_interactive(access_token)


def _split_valid_domains(raw: List[str]) -> Tuple[List[str], List[str]]:
    valid   = [d for d in raw if DOMAIN_PATTERN.match(d)]
    invalid = [d for d in raw if not DOMAIN_PATTERN.match(d)]
    return valid, invalid


if __name__ == "__main__":
    main()
