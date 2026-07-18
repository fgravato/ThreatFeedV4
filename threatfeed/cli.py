"""Command-line interface: modern subcommands plus backward-compatible legacy flags."""

import argparse
import logging
import sys
from dataclasses import asdict
from pathlib import Path
from typing import List, Optional

from . import __version__, config
from .client import ThreatFeedClient, ThreatFeedError
from .domains import DomainDiff, make_diff, parse_domain_lines
from .output import err, info, ok, print_diff, print_json, print_table

logger = logging.getLogger(__name__)


# ── Parser ────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="threatfeed",
        description="Manage Lookout threat feeds via the Lookout REST API.",
        epilog="Run with no command to start the interactive menu.",
    )
    parser.add_argument("--json", action="store_true",
                        help="machine-readable JSON output")
    parser.add_argument("--version", action="store_true",
                        help="print version and exit")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="enable debug logging")

    legacy = parser.add_argument_group(
        "legacy flags", "kept for backward compatibility — prefer the subcommands"
    )
    legacy.add_argument("--list-feeds", action="store_true", help="list all feeds")
    legacy.add_argument("--create-feed", nargs=2, metavar=("TITLE", "DESC"),
                        help="create a CSV feed")
    legacy.add_argument("--view-feed", metavar="FEED_ID",
                        help="print feed metadata as JSON")
    legacy.add_argument("--delete-feed", metavar="FEED_ID",
                        help="delete a feed without confirmation")
    legacy.add_argument("--add-domain", nargs="+", metavar=("FEED_ID", "DOMAIN"),
                        help="add one or more domains")
    legacy.add_argument("--remove-domain", nargs="+", metavar=("FEED_ID", "DOMAIN"),
                        help="remove one or more domains")
    legacy.add_argument("--add-domains-file", nargs=2, metavar=("FEED_ID", "FILE"),
                        help="add domains listed in FILE")
    legacy.add_argument("--remove-domains-file", nargs=2, metavar=("FEED_ID", "FILE"),
                        help="remove domains listed in FILE")
    legacy.add_argument("--update-feed", nargs=2, metavar=("FEED_ID", "SOURCE_URL"),
                        help="update feed content from a URL")
    legacy.add_argument("--upload-type", dest="legacy_upload_type",
                        choices=["INCREMENTAL", "OVERWRITE"], default="OVERWRITE",
                        help="upload mode for --update-feed (default: OVERWRITE)")
    legacy.add_argument("--no-verify-ssl", dest="legacy_no_verify_ssl", action="store_true",
                        help="disable SSL verification for --update-feed downloads")

    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    sub.add_parser("list", help="list all feeds")

    sp = sub.add_parser("create", help="create a new CSV feed")
    sp.add_argument("title")
    sp.add_argument("description")

    sp = sub.add_parser("view", help="print feed metadata as JSON")
    sp.add_argument("feed_id")

    sp = sub.add_parser("delete", help="delete a feed (asks for confirmation)")
    sp.add_argument("feed_id")
    sp.add_argument("-y", "--yes", action="store_true", help="skip confirmation")

    sp = sub.add_parser("add", help="add domains to a feed")
    sp.add_argument("feed_id")
    sp.add_argument("domains", nargs="*", help="domains to add")
    sp.add_argument("--file", help="read domains from a file (one per line)")
    sp.add_argument("--dry-run", action="store_true", help="preview changes only")

    sp = sub.add_parser("remove", help="remove domains from a feed")
    sp.add_argument("feed_id")
    sp.add_argument("domains", nargs="*", help="domains to remove")
    sp.add_argument("--file", help="read domains from a file (one per line)")
    sp.add_argument("--dry-run", action="store_true", help="preview changes only")
    sp.add_argument("-y", "--yes", action="store_true", help="skip confirmation")

    sp = sub.add_parser("update", help="update feed content from a URL")
    sp.add_argument("feed_id")
    sp.add_argument("source_url")
    sp.add_argument("--upload-type", choices=["INCREMENTAL", "OVERWRITE"],
                    default="OVERWRITE", help="upload mode (default: OVERWRITE)")
    sp.add_argument("--no-verify-ssl", action="store_true",
                    help="disable SSL verification for the download")
    sp.add_argument("--dry-run", action="store_true", help="preview changes only")
    sp.add_argument("-y", "--yes", action="store_true", help="skip confirmation")

    sp = sub.add_parser("export", help="export feed domains to a file or stdout")
    sp.add_argument("feed_id")
    sp.add_argument("-o", "--output", help="output file (default: stdout)")

    sp = sub.add_parser("search", help="find domains containing a pattern")
    sp.add_argument("feed_id")
    sp.add_argument("pattern")

    return parser


# ── Shared helpers ────────────────────────────────────────────────────────────

def _confirm(question: str) -> bool:
    try:
        return input(f"{question}  Type 'yes' to confirm: ").strip().lower() == "yes"
    except EOFError:
        return False


def _gather_domains(positional: Optional[List[str]], file_path: Optional[str]) -> List[str]:
    """Merge positional domains and file contents, then validate once."""
    raw = list(positional or [])
    if file_path:
        try:
            raw.extend(Path(file_path).read_text(encoding="utf-8").splitlines())
        except OSError as e:
            raise ThreatFeedError(f"cannot read domain file '{file_path}': {e}")
    valid, invalid = parse_domain_lines(raw)
    if invalid:
        preview = ", ".join(invalid[:5]) + (", ..." if len(invalid) > 5 else "")
        print(f"warning: skipped {len(invalid)} invalid domain(s): {preview}", file=sys.stderr)
    return valid


def _show_diff(diff: DomainDiff, json_mode: bool) -> None:
    if json_mode:
        print_json(asdict(diff))
    else:
        print_diff(diff)


# ── Command handlers ──────────────────────────────────────────────────────────

def cmd_list(client: ThreatFeedClient, args) -> int:
    feeds = client.list_feeds()
    if args.json:
        print_json(feeds)
        return 0
    if not feeds:
        print("No threat feeds found.")
        return 0
    rows = [
        (
            str(i),
            (f.get("title") or f["feedId"])[:40],
            "?" if "error" in f else str(f.get("elementsCount", 0)),
            "error" if "error" in f else (f.get("elementsUploadedAt") or "never")[:10],
            f["feedId"],
        )
        for i, f in enumerate(feeds, 1)
    ]
    print()
    print_table(["#", "Title", "Domains", "Updated", "Feed ID"], rows)
    print()
    return 0


def cmd_create(client: ThreatFeedClient, args) -> int:
    feed_id = client.create_feed(args.title, args.description)
    if args.json:
        print_json({"feedId": feed_id})
    else:
        ok(f"Feed created: {feed_id}")
    return 0


def cmd_view(client: ThreatFeedClient, args) -> int:
    print_json(client.get_feed_metadata(args.feed_id))
    return 0


def cmd_delete(client: ThreatFeedClient, args) -> int:
    if not args.yes and not _confirm(f"Permanently delete feed {args.feed_id}?"):
        info("Cancelled.")
        return 0
    client.delete_feed(args.feed_id)
    ok(f"Feed {args.feed_id} deleted.")
    return 0


def cmd_add(client: ThreatFeedClient, args) -> int:
    domains = _gather_domains(args.domains, args.file)
    if not domains:
        err("no valid domains to add.")
        return 1
    if args.dry_run:
        current = client.get_domains(args.feed_id)
        _show_diff(make_diff(current, sorted(set(current) | set(domains))), args.json)
        info("Dry run — no changes applied.")
        return 0
    count = client.upload_domains(args.feed_id, [(d, "add") for d in domains], "INCREMENTAL")
    ok(f"Added {count} domain(s) to {args.feed_id}.")
    return 0


def _remove_diff(client: ThreatFeedClient, feed_id: str, targets: List[str]) -> DomainDiff:
    current = client.get_domains(feed_id)
    current_set, target_set = set(current), set(targets)
    return DomainDiff(
        len(current),
        added=[],
        removed=sorted(target_set & current_set),
        unchanged=sorted(current_set - target_set),
    )


def cmd_remove(client: ThreatFeedClient, args) -> int:
    domains = _gather_domains(args.domains, args.file)
    if not domains:
        err("no valid domains to remove.")
        return 1
    diff = _remove_diff(client, args.feed_id, domains)
    _show_diff(diff, args.json)
    if args.dry_run:
        info("Dry run — no changes applied.")
        return 0
    if not diff.removed:
        info("None of those domains are in the feed.")
        return 0
    if not args.yes and not _confirm(f"Remove {len(diff.removed)} domain(s) from {args.feed_id}?"):
        info("Cancelled.")
        return 0
    count = client.upload_domains(
        args.feed_id, [(d, "delete") for d in diff.removed], "INCREMENTAL"
    )
    ok(f"Removed {count} domain(s) from {args.feed_id}.")
    return 0


def cmd_update(client: ThreatFeedClient, args) -> int:
    extracted = client.download_domains(args.source_url, verify_ssl=not args.no_verify_ssl)
    if not extracted:
        err(f"no valid domains found in content from {args.source_url}")
        return 1
    if args.upload_type == "OVERWRITE":
        diff = client.preview_changes(args.feed_id, extracted)
    else:
        current = client.get_domains(args.feed_id)
        diff = make_diff(current, sorted(set(current) | set(extracted)))
    _show_diff(diff, args.json)
    if args.dry_run:
        info("Dry run — no changes applied.")
        return 0
    if args.upload_type == "OVERWRITE" and not args.yes:
        if not _confirm("Apply this OVERWRITE?"):
            info("Cancelled.")
            return 0
    action = "add" if args.upload_type == "INCREMENTAL" else None
    count = client.upload_domains(args.feed_id, [(d, action) for d in extracted], args.upload_type)
    ok(f"Uploaded {count} domain(s) to {args.feed_id} ({args.upload_type}).")
    return 0


def cmd_export(client: ThreatFeedClient, args) -> int:
    domains = client.get_domains(args.feed_id)
    if args.json:
        print_json({"feedId": args.feed_id, "count": len(domains), "domains": domains})
        return 0
    if args.output:
        try:
            Path(args.output).write_text("\n".join(domains) + ("\n" if domains else ""),
                                         encoding="utf-8")
        except OSError as e:
            err(f"cannot write '{args.output}': {e}")
            return 1
        ok(f"Exported {len(domains)} domain(s) to {args.output}")
    else:
        if domains:
            print("\n".join(domains))
    return 0


def cmd_search(client: ThreatFeedClient, args) -> int:
    domains = client.get_domains(args.feed_id)
    term = args.pattern.lower()
    matches = [d for d in domains if term in d]
    if args.json:
        print_json({"feedId": args.feed_id, "pattern": args.pattern,
                    "count": len(matches), "matches": matches})
        return 0
    for i, domain in enumerate(matches, 1):
        print(f"{i:>4}.  {domain}")
    if matches:
        info(f"{len(matches)} of {len(domains)} domains match '{args.pattern}'.")
    else:
        info(f"No domains in {args.feed_id} match '{args.pattern}'.")
    return 0


COMMANDS = {
    "list": cmd_list,
    "create": cmd_create,
    "view": cmd_view,
    "delete": cmd_delete,
    "add": cmd_add,
    "remove": cmd_remove,
    "update": cmd_update,
    "export": cmd_export,
    "search": cmd_search,
}


# ── Legacy flag dispatch ──────────────────────────────────────────────────────

def run_legacy(client: ThreatFeedClient, args) -> Optional[int]:
    """Map pre-2.0 flags onto the command handlers. Returns None if none were given."""
    if args.list_feeds:
        return cmd_list(client, args)
    if args.create_feed:
        args.title, args.description = args.create_feed
        return cmd_create(client, args)
    if args.view_feed:
        args.feed_id = args.view_feed
        return cmd_view(client, args)
    if args.delete_feed:
        args.feed_id = args.delete_feed
        args.yes = True  # legacy behavior: no interactive confirmation
        return cmd_delete(client, args)
    if args.update_feed:
        args.feed_id, args.source_url = args.update_feed
        args.upload_type = args.legacy_upload_type
        args.no_verify_ssl = args.legacy_no_verify_ssl
        args.dry_run = False
        args.yes = True  # legacy behavior: no interactive confirmation
        return cmd_update(client, args)
    if args.add_domain:
        args.feed_id, args.domains = args.add_domain[0], args.add_domain[1:]
        args.file, args.dry_run = None, False
        return cmd_add(client, args)
    if args.remove_domain:
        args.feed_id, args.domains = args.remove_domain[0], args.remove_domain[1:]
        args.file, args.dry_run = None, False
        args.yes = True  # legacy behavior: no interactive confirmation
        return cmd_remove(client, args)
    if args.add_domains_file:
        args.feed_id, args.file = args.add_domains_file
        args.domains, args.dry_run = [], False
        return cmd_add(client, args)
    if args.remove_domains_file:
        args.feed_id, args.file = args.remove_domains_file
        args.domains, args.dry_run = [], False
        args.yes = True  # legacy behavior: no interactive confirmation
        return cmd_remove(client, args)
    return None


# ── Entry point ───────────────────────────────────────────────────────────────

def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    if args.version:
        print(f"threatfeed {__version__}")
        return 0

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    api_key = config.load_api_key()
    if not api_key:
        err(config.api_key_hint())
        return 1

    try:
        client = ThreatFeedClient(api_key)
        if args.command:
            return COMMANDS[args.command](client, args)
        legacy_rc = run_legacy(client, args)
        if legacy_rc is not None:
            return legacy_rc
        from .interactive import run_interactive
        run_interactive(client)
        return 0
    except ThreatFeedError as e:
        err(str(e))
        return 1
    except ValueError as e:
        err(str(e))
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
