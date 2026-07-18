"""Domain validation, normalization, deduplication, and CSV serialization.

This module is the single source of truth for how domains are parsed and
validated — both the CLI and the interactive UI use these helpers.
"""

import csv
import io
import re
from typing import Iterable, List, Optional, Sequence, Tuple

# Applied to normalized (lowercased) values. Rejects IPs, bare hostnames,
# leading/trailing hyphens, and labels over 63 chars.
DOMAIN_PATTERN = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$")


def normalize_domain(raw: str) -> str:
    """Lowercase, strip surrounding whitespace, and drop a trailing dot (FQDN form)."""
    d = raw.strip().lower()
    if d.endswith("."):
        d = d[:-1]
    return d


def is_valid_domain(raw: str) -> bool:
    return bool(DOMAIN_PATTERN.match(normalize_domain(raw)))


def parse_domain_lines(lines: Iterable[str]) -> Tuple[List[str], List[str]]:
    """Parse domains from raw text lines (files or pasted input).

    Skips blank lines and '#' comment lines, normalizes entries, and dedups
    while preserving first-seen order.

    Returns (valid, invalid): normalized valid domains and the raw invalid entries.
    """
    valid: List[str] = []
    invalid: List[str] = []
    seen = set()
    for raw in lines:
        entry = raw.strip()
        if not entry or entry.startswith("#"):
            continue
        normalized = normalize_domain(entry)
        if not DOMAIN_PATTERN.match(normalized):
            invalid.append(entry)
            continue
        if normalized not in seen:
            seen.add(normalized)
            valid.append(normalized)
    return valid, invalid


def parse_domain_text(text: str) -> Tuple[List[str], List[str]]:
    """Parse domains from a blob of text (one per line)."""
    return parse_domain_lines(text.splitlines())


def load_domain_file(path: str) -> Tuple[List[str], List[str]]:
    """Read and parse a domain file. Raises OSError subclasses on failure."""
    with open(path, encoding="utf-8") as f:
        return parse_domain_lines(f)


def build_csv(domains: Sequence[Tuple[str, Optional[str]]], upload_type: str) -> str:
    """Serialize domains to the CSV payload expected by the elements endpoint.

    INCREMENTAL rows are (domain, action) where action is 'add' or 'delete';
    OVERWRITE rows are domain-only and the action is ignored.
    """
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    if upload_type == "INCREMENTAL":
        writer.writerow(["domain", "action"])
        for domain, action in domains:
            writer.writerow([domain, action])
    else:
        writer.writerow(["domain"])
        for domain, _ in domains:
            writer.writerow([domain])
    return buf.getvalue()


def parse_elements_csv(text: str) -> List[str]:
    """Parse the CSV returned by GET /elements into a list of domains.

    Tolerates CRLF line endings, blank lines, and a missing header row.
    """
    rows = [row for row in csv.reader(io.StringIO(text)) if row]
    if not rows:
        return []
    if rows[0] and rows[0][0].strip().lower() == "domain":
        rows = rows[1:]
    return [row[0].strip() for row in rows if row and row[0].strip()]


def diff_domains(
    current: Iterable[str], desired: Iterable[str]
) -> Tuple[List[str], List[str], List[str]]:
    """Compare the current feed contents with the desired final state.

    Returns (added, removed, unchanged) as sorted lists of normalized domains:
    domains that would be added, domains that would be removed, and domains
    present in both.
    """
    cur = {normalize_domain(d) for d in current}
    new = {normalize_domain(d) for d in desired}
    return sorted(new - cur), sorted(cur - new), sorted(cur & new)
