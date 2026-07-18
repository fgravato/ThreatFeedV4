"""Interactive menu-driven interface for threat feed management."""

import os
import sys
from dataclasses import dataclass, field
from typing import List, Optional

from .client import DomainDiff, ThreatFeedClient, ThreatFeedError
from .domains import diff_domains, parse_domain_lines
from .output import Colors, colorize, divider

PAGE_SIZE = 20


# ── Menu state ────────────────────────────────────────────────────────────────

@dataclass
class MenuContext:
    current_feed_id: Optional[str] = None
    current_feed_title: Optional[str] = None
    breadcrumb: List[str] = field(default_factory=lambda: ["Main Menu"])

    def update_feed(self, feed_id: Optional[str], title: Optional[str]) -> None:
        self.current_feed_id = feed_id
        self.current_feed_title = title

    def push(self, name: str) -> None:
        self.breadcrumb.append(name)

    def pop(self) -> None:
        if len(self.breadcrumb) > 1:
            self.breadcrumb.pop()

    def reset(self) -> None:
        self.breadcrumb = ["Main Menu"]
        self.update_feed(None, None)


# ── Small UI helpers ──────────────────────────────────────────────────────────

def _header(ctx: MenuContext) -> None:
    print()
    divider()
    print(colorize("  Threat Feed Management System", Colors.HEADER, Colors.BOLD))
    print(colorize("  " + " > ".join(ctx.breadcrumb), Colors.BLUE))
    if ctx.current_feed_title:
        print(colorize(f"  Feed: {ctx.current_feed_title}", Colors.YELLOW))
    divider()


def _nav_hint(*extras: str) -> None:
    parts = list(extras) + ["b: back", "q: quit"]
    print(colorize("\n  " + " | ".join(parts), Colors.GREEN))


def _prompt(msg: str) -> str:
    try:
        return input(f"\n  {msg}: ").strip()
    except EOFError:
        return "q"


def _ok(msg: str) -> None:
    print(colorize(f"\n  {msg}", Colors.GREEN))


def _err(msg: str) -> None:
    print(colorize(f"\n  {msg}", Colors.RED))


def _info(msg: str) -> None:
    print(colorize(f"\n  {msg}", Colors.YELLOW))


def _is_back(choice: str) -> bool:
    return choice.lower() == "b"


def _is_quit(choice: str) -> bool:
    return choice.lower() == "q"


def _confirm(question: str) -> bool:
    return _prompt(f"{question}  Type 'yes' to confirm").lower() == "yes"


def _print_diff_summary(diff: DomainDiff) -> None:
    print(f"\n  Current domains: {diff.current_count}")
    print(colorize(f"  + {len(diff.added)} to add", Colors.GREEN))
    print(colorize(f"  - {len(diff.removed)} to remove", Colors.RED))
    print(f"  = {len(diff.unchanged)} unchanged")
    for label, items, color in (
        ("add", diff.added, Colors.GREEN),
        ("remove", diff.removed, Colors.RED),
    ):
        if items:
            preview = ", ".join(items[:10]) + (", ..." if len(items) > 10 else "")
            print(colorize(f"    {label}: {preview}", color))
    if not diff.changed:
        _info("No changes — the feed already matches.")


# ── Input helper ──────────────────────────────────────────────────────────────

def _read_domain_input(raw: str) -> Optional[List[str]]:
    """Accept either a file path or space-separated domains. Returns domains or None."""
    lines: List[str]
    if os.path.exists(raw):
        try:
            with open(raw, encoding="utf-8") as f:
                lines = f.read().splitlines()
        except OSError as e:
            _err(f"Cannot read file: {e}")
            return None
    else:
        lines = raw.split()

    valid, invalid = parse_domain_lines(lines)
    if invalid:
        preview = ", ".join(invalid[:5]) + (", ..." if len(invalid) > 5 else "")
        _err(f"Skipped {len(invalid)} invalid: {preview}")
    if not valid:
        _err("No valid domains to process.")
        return None
    return valid


# ── Screens ───────────────────────────────────────────────────────────────────

def browse_feeds(client: ThreatFeedClient, ctx: MenuContext) -> None:
    ctx.push("Feeds")
    while True:
        _header(ctx)
        _info("Loading feeds...")
        try:
            feeds = client.list_feeds()
        except ThreatFeedError as e:
            _err(str(e))
            _nav_hint("r: retry")
            choice = _prompt("Choice")
            if _is_quit(choice):
                sys.exit(0)
            if choice.lower() == "r":
                continue
            ctx.pop()
            return

        # Clear the "Loading..." line feel by re-printing the table header.
        print(f"\n  {'#':<4} {'Title':<36} {'Domains':>8}  Updated")
        divider("-")
        for i, feed in enumerate(feeds, 1):
            title = (feed.get("title") or feed["feedId"])[:35]
            if "error" in feed:
                count, updated = "?", "error"
            else:
                count = feed.get("elementsCount", 0)
                updated = (feed.get("elementsUploadedAt") or "never")[:10]
            print(
                f"  {colorize(f'{i:<4}', Colors.BOLD)} "
                f"{colorize(f'{title:<36}', Colors.BLUE)} {count:>8}  {updated}"
            )
        if not feeds:
            _info("No threat feeds found.")
        divider("-")

        _nav_hint("number: open feed", "r: refresh")
        choice = _prompt(f"Select feed (1–{len(feeds)})")

        if _is_quit(choice):
            sys.exit(0)
        if _is_back(choice):
            ctx.pop()
            return
        if choice.lower() == "r":
            continue
        try:
            idx = int(choice)
            if 1 <= idx <= len(feeds):
                manage_single_feed(feeds[idx - 1]["feedId"], client, ctx)
            else:
                _err(f"Enter a number between 1 and {len(feeds)}.")
        except ValueError:
            _err("Enter a feed number or shortcut key.")


def manage_single_feed(feed_id: str, client: ThreatFeedClient, ctx: MenuContext) -> None:
    ctx.update_feed(feed_id, feed_id)
    ctx.push(feed_id[:35])

    while True:
        try:
            meta = client.get_feed_metadata(feed_id)
        except ThreatFeedError as e:
            _err(str(e))
            ctx.pop()
            ctx.update_feed(None, None)
            return

        title = meta.get("title", feed_id)
        ctx.update_feed(feed_id, title)
        ctx.breadcrumb[-1] = title[:35]
        _header(ctx)

        updated = (meta.get("elementsUploadedAt") or "never")[:19]
        print(colorize("\n  Description:", Colors.BLUE), meta.get("description", ""))
        print(colorize("  Type:       ", Colors.BLUE), meta.get("feedType", ""))
        print(colorize("  Domains:    ", Colors.BLUE), meta.get("elementsCount", 0))
        print(colorize("  Updated:    ", Colors.BLUE), updated)

        options = [
            "View / search domains",
            "Add domain(s)",
            "Remove domain(s)",
            "Update from URL",
            "Export domains to file",
            "Delete this feed",
        ]
        print()
        for i, label in enumerate(options, 1):
            print(f"  {colorize(f'{i}.', Colors.BOLD)} {label}")
        _nav_hint()

        choice = _prompt("Choice")
        if _is_quit(choice):
            sys.exit(0)
        if _is_back(choice):
            ctx.pop()
            ctx.update_feed(None, None)
            return

        if choice == "1":
            view_domains(feed_id, client, ctx)
        elif choice == "2":
            _add_domains(feed_id, client, ctx)
        elif choice == "3":
            _remove_domains(feed_id, client, ctx)
        elif choice == "4":
            _update_from_url(feed_id, client, ctx)
        elif choice == "5":
            _export_domains(feed_id, client, ctx)
        elif choice == "6":
            if _delete_feed(feed_id, title, client, ctx):
                return
        else:
            _err(f"Enter 1–{len(options)} or a shortcut key.")


def view_domains(feed_id: str, client: ThreatFeedClient, ctx: MenuContext) -> None:
    ctx.push("Domains")
    try:
        domains = client.get_domains(feed_id)
    except ThreatFeedError as e:
        _err(str(e))
        ctx.pop()
        return

    if not domains:
        _header(ctx)
        _info("No domains in this feed.")
        _prompt("Press Enter to go back")
        ctx.pop()
        return

    page = 0
    filtered: Optional[List[str]] = None  # None = no active filter

    while True:
        shown = filtered if filtered is not None else domains
        total_pages = max(1, (len(shown) + PAGE_SIZE - 1) // PAGE_SIZE)
        page = min(page, total_pages - 1)
        start, end = page * PAGE_SIZE, min((page + 1) * PAGE_SIZE, len(shown))

        _header(ctx)
        scope = (
            colorize(f"filter matches {len(shown)} of {len(domains)}", Colors.CYAN)
            if filtered is not None
            else colorize(str(len(domains)), Colors.GREEN) + " domains"
        )
        print(f"\n  {start + 1}–{end} | {scope}"
              f"  (page {colorize(str(page + 1), Colors.YELLOW)}/{total_pages})\n")

        for j, domain in enumerate(shown[start:end]):
            color = Colors.BLUE if j % 2 == 0 else ""
            line = f"  {start + j + 1:>4}.  {domain}"
            print(colorize(line, color) if color else line)

        divider("-")
        hints = ["/text: filter", "/: clear filter"]
        if page < total_pages - 1:
            hints.insert(0, "n: next page")
        if page > 0:
            hints.insert(0 if page >= total_pages - 1 else 1, "p: prev page")
        _nav_hint(*hints)

        choice = _prompt("Choice")
        low = choice.lower()
        if _is_quit(low) or _is_back(low) or low == "":
            break
        if low == "n":
            if page < total_pages - 1:
                page += 1
            else:
                _err("Already on the last page.")
        elif low == "p":
            if page > 0:
                page -= 1
            else:
                _err("Already on the first page.")
        elif choice.startswith("/"):
            term = choice[1:].strip().lower()
            if not term:
                filtered = None
                page = 0
            else:
                filtered = [d for d in domains if term in d]
                page = 0
                if not filtered:
                    _info(f"No domains match '{term}'. Filter cleared.")
                    filtered = None
        else:
            _err("Use n/p to page, /text to filter, or b to go back.")

    ctx.pop()


def _add_domains(feed_id: str, client: ThreatFeedClient, ctx: MenuContext) -> None:
    ctx.push("Add Domains")
    _header(ctx)
    print("\n  Enter space-separated domains, or a path to a file (one per line).")
    print("  Examples:  evil.com phishing.net malware.org")
    print("             /path/to/domains.txt")
    raw = _prompt("Domains or file path")
    ctx.pop()

    if not raw or _is_back(raw) or _is_quit(raw):
        return
    domains = _read_domain_input(raw)
    if not domains:
        return

    _info(f"Adding {len(domains)} domain(s)...")
    try:
        count = client.upload_domains(feed_id, [(d, "add") for d in domains], "INCREMENTAL")
        _ok(f"{count} domain(s) added.")
    except ThreatFeedError as e:
        _err(str(e))


def _remove_domains(feed_id: str, client: ThreatFeedClient, ctx: MenuContext) -> None:
    ctx.push("Remove Domains")
    _header(ctx)
    print("\n  Enter space-separated domains, or a path to a file (one per line).")
    raw = _prompt("Domains or file path")

    if not raw or _is_back(raw) or _is_quit(raw):
        ctx.pop()
        return
    targets = _read_domain_input(raw)
    if not targets:
        ctx.pop()
        return

    try:
        current = client.get_domains(feed_id)
    except ThreatFeedError as e:
        _err(str(e))
        ctx.pop()
        return

    current_set = set(current)
    target_set = set(targets)
    present = sorted(target_set & current_set)
    _print_diff_summary(DomainDiff(
        len(current),
        added=[],
        removed=present,
        unchanged=sorted(current_set - target_set),
    ))
    if not present:
        _info("None of those domains are in the feed.")
        ctx.pop()
        return
    if not _confirm(f"Remove {len(present)} domain(s) from this feed?"):
        _info("Cancelled.")
        ctx.pop()
        return

    try:
        count = client.upload_domains(feed_id, [(d, "delete") for d in present], "INCREMENTAL")
        _ok(f"{count} domain(s) removed.")
    except ThreatFeedError as e:
        _err(str(e))
    ctx.pop()


def _update_from_url(feed_id: str, client: ThreatFeedClient, ctx: MenuContext) -> None:
    ctx.push("Update from URL")
    _header(ctx)
    print("\n  Download domains from a URL and upload them to this feed.")
    url = _prompt("Source URL (http/https)")

    if not url or _is_back(url) or _is_quit(url):
        ctx.pop()
        return

    print(f"\n  {colorize('Upload type:', Colors.BOLD)}")
    print(f"  {colorize('1.', Colors.BOLD)} OVERWRITE    – replace all existing domains")
    print(f"  {colorize('2.', Colors.BOLD)} INCREMENTAL  – merge new domains into existing ones")
    upload_choice = _prompt("Choice (1/2, default 1)")
    upload_type = "INCREMENTAL" if upload_choice == "2" else "OVERWRITE"

    _info("Downloading source and computing changes...")
    try:
        extracted = client.download_domains(url)
        if not extracted:
            _err("No valid domains found in source content.")
            ctx.pop()
            return
        current = client.get_domains(feed_id)
        if upload_type == "OVERWRITE":
            desired = extracted
        else:
            desired = sorted(set(current) | set(extracted))
        added, removed, unchanged = diff_domains(current, desired)
        _print_diff_summary(DomainDiff(len(current), added, removed, unchanged))

        if upload_type == "OVERWRITE" and not _confirm("Apply this OVERWRITE?"):
            _info("Cancelled.")
            ctx.pop()
            return

        action = "add" if upload_type == "INCREMENTAL" else None
        count = client.upload_domains(feed_id, [(d, action) for d in extracted], upload_type)
        _ok(f"Feed content updated ({count} domains uploaded).")
    except (ThreatFeedError, ValueError) as e:
        _err(str(e))
    ctx.pop()


def _export_domains(feed_id: str, client: ThreatFeedClient, ctx: MenuContext) -> None:
    ctx.push("Export Domains")
    _header(ctx)
    raw = _prompt("Output file path")
    ctx.pop()

    if not raw or _is_back(raw) or _is_quit(raw):
        return
    try:
        domains = client.get_domains(feed_id)
        with open(raw, "w", encoding="utf-8") as f:
            f.write("\n".join(domains) + ("\n" if domains else ""))
        _ok(f"Exported {len(domains)} domain(s) to {raw}")
    except ThreatFeedError as e:
        _err(str(e))
    except OSError as e:
        _err(f"Cannot write file: {e}")


def _delete_feed(feed_id: str, title: str, client: ThreatFeedClient, ctx: MenuContext) -> bool:
    """Returns True if the feed was deleted (caller should exit the feed loop)."""
    ctx.push("Delete Feed")
    _header(ctx)
    print(colorize("\n  You are about to permanently delete:", Colors.RED))
    print(f"  Title:   {title}")
    print(f"  Feed ID: {feed_id}")
    confirmed = _confirm("Delete this feed?")
    ctx.pop()

    if not confirmed:
        _info("Deletion cancelled.")
        return False
    try:
        client.delete_feed(feed_id)
        _ok(f"Feed '{title}' deleted.")
        ctx.reset()
        return True
    except ThreatFeedError as e:
        _err(str(e))
        return False


def create_new_feed(client: ThreatFeedClient, ctx: MenuContext) -> None:
    ctx.push("Create Feed")
    _header(ctx)
    print("\n  Feed type is CSV (the only supported type).")
    print("  Title and description must each be 8–255 characters.\n")
    title = _prompt("Title")
    description = _prompt("Description")
    ctx.pop()

    if not title or not description:
        _err("Title and description are required.")
        return

    _info("Creating feed...")
    try:
        feed_id = client.create_feed(title, description)
        _ok(f"Feed created.  ID: {colorize(feed_id, Colors.CYAN)}")
    except (ThreatFeedError, ValueError) as e:
        _err(str(e))


# ── Main loop ─────────────────────────────────────────────────────────────────

def run_interactive(client: ThreatFeedClient) -> None:
    ctx = MenuContext()
    while True:
        _header(ctx)
        print(f"\n  {colorize('1.', Colors.BOLD)} Browse and manage feeds")
        print(f"  {colorize('2.', Colors.BOLD)} Create a new feed")
        print(f"  {colorize('3.', Colors.BOLD)} Exit")
        _nav_hint()

        choice = _prompt("Choice")
        if _is_quit(choice) or choice == "3":
            print(colorize("\n  Goodbye!", Colors.GREEN))
            return
        if choice == "1":
            browse_feeds(client, ctx)
        elif choice == "2":
            create_new_feed(client, ctx)
        else:
            _err("Enter 1, 2, or 3.")
