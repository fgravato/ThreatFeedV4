"""HTTP client for the Lookout threat-feeds API.

Encapsulates authentication (with automatic token refresh), connection
pooling, retries with backoff, timeouts, and consistent error reporting.
"""

import logging
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlparse

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from . import config
from .domains import build_csv, diff_domains, extract_domains_from_text, parse_elements_csv

logger = logging.getLogger(__name__)


class ThreatFeedError(Exception):
    """An API operation failed. `status` is the HTTP status code, if any."""

    def __init__(self, message: str, status: Optional[int] = None):
        super().__init__(message)
        self.status = status


class AuthenticationError(ThreatFeedError):
    """The API key was rejected or the token endpoint failed."""


@dataclass
class DomainDiff:
    """What an upload would change, computed against live feed contents."""

    current_count: int
    added: List[str] = field(default_factory=list)
    removed: List[str] = field(default_factory=list)
    unchanged: List[str] = field(default_factory=list)

    @property
    def changed(self) -> bool:
        return bool(self.added or self.removed)


class ThreatFeedClient:
    """Stateful client for the threat-feeds API.

    A single requests.Session is reused for all calls (connection pooling).
    Retries with exponential backoff are applied to 429/5xx responses, and an
    expired bearer token is transparently refreshed once per request.
    """

    RETRY_STATUS_CODES = (429, 500, 502, 503, 504)

    def __init__(
        self,
        api_key: str,
        timeout: Tuple[int, int] = config.DEFAULT_TIMEOUT,
        max_workers: int = 8,
    ):
        if not api_key:
            raise AuthenticationError("empty API key")
        self._api_key = api_key
        self._timeout = timeout
        self._max_workers = max_workers
        self._token: Optional[str] = None

        self.session = requests.Session()
        retry = Retry(
            total=3,
            backoff_factor=0.5,
            status_forcelist=self.RETRY_STATUS_CODES,
            allowed_methods={"GET", "POST", "DELETE"},
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)

    # ── Authentication ──────────────────────────────────────────────────────

    @property
    def token(self) -> str:
        if self._token is None:
            self._token = self._fetch_token()
        return self._token

    def _fetch_token(self) -> str:
        try:
            r = self.session.post(
                config.TOKEN_URL,
                headers={
                    "Accept": "application/json",
                    "Authorization": f"Bearer {self._api_key}",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                data={"grant_type": "client_credentials"},
                timeout=self._timeout,
            )
        except requests.RequestException as e:
            raise AuthenticationError(f"token request failed: {e}") from e
        if r.status_code != 200:
            raise AuthenticationError(
                f"token request failed: HTTP {r.status_code} — {self._error_detail(r)}",
                status=r.status_code,
            )
        try:
            token = r.json().get("access_token")
        except ValueError:
            token = None
        if not token:
            raise AuthenticationError("token response did not contain an access_token")
        return token

    # ── Core request handling ───────────────────────────────────────────────

    def _request(self, method: str, path: str, _retried: bool = False, **kwargs) -> requests.Response:
        url = f"{config.BASE_URL}{path}"
        headers = kwargs.pop("headers", {})
        headers["Authorization"] = f"Bearer {self.token}"
        headers.setdefault("Accept", "application/json")
        kwargs.setdefault("timeout", self._timeout)

        try:
            r = self.session.request(method, url, headers=headers, **kwargs)
        except requests.RequestException as e:
            raise ThreatFeedError(f"{method} {path} failed: {e}") from e

        if r.status_code == 401 and not _retried:
            logger.info("bearer token rejected (401); refreshing and retrying")
            self._token = None
            return self._request(method, path, _retried=True, **kwargs)

        if r.status_code >= 400:
            raise ThreatFeedError(
                f"{method} {path} failed: HTTP {r.status_code} — {self._error_detail(r)}",
                status=r.status_code,
            )
        return r

    @staticmethod
    def _error_detail(r: requests.Response) -> str:
        try:
            body = r.json()
            detail = body.get("detail") or body.get("message")
            if detail:
                return str(detail)
        except ValueError:
            pass
        return (r.text or "").strip()[:200] or "no response body"

    @staticmethod
    def _json(r: requests.Response):
        try:
            return r.json()
        except ValueError as e:
            raise ThreatFeedError(f"invalid JSON in API response: {e}") from e

    # ── Feed operations ─────────────────────────────────────────────────────

    def list_feed_ids(self) -> List[str]:
        return self._json(self._request("GET", "/threat-feeds"))

    def get_feed_metadata(self, feed_id: str) -> Dict:
        return self._json(self._request("GET", f"/threat-feeds/{feed_id}"))

    def list_feeds(self) -> List[Dict]:
        """All feeds with their metadata, fetched in parallel.

        Each entry is the feed metadata dict plus a 'feedId' key. Feeds whose
        metadata cannot be fetched are included with an 'error' key rather
        than failing the whole listing.
        """
        feed_ids = self.list_feed_ids()
        if not feed_ids:
            return []

        def fetch(feed_id: str) -> Dict:
            try:
                return {"feedId": feed_id, **self.get_feed_metadata(feed_id)}
            except ThreatFeedError as e:
                logger.warning("metadata fetch failed for %s: %s", feed_id, e)
                return {"feedId": feed_id, "title": feed_id, "error": str(e)}

        with ThreadPoolExecutor(max_workers=self._max_workers) as pool:
            return list(pool.map(fetch, feed_ids))

    def create_feed(self, title: str, description: str) -> str:
        for label, value in (("Title", title), ("Description", description)):
            if not 8 <= len(value) <= 255:
                raise ValueError(f"{label} must be 8–255 characters (got {len(value)}).")
        r = self._request(
            "POST",
            "/threat-feeds",
            json={"feedType": "CSV", "title": title, "description": description},
        )
        return self._json(r)["feedId"]

    def delete_feed(self, feed_id: str) -> None:
        self._request("DELETE", f"/threat-feeds/{feed_id}")

    # ── Domain operations ───────────────────────────────────────────────────

    def get_domains(self, feed_id: str) -> List[str]:
        r = self._request(
            "GET",
            f"/threat-feeds/{feed_id}/elements",
            headers={"Accept": "text/csv"},
        )
        return parse_elements_csv(r.text)

    def upload_domains(
        self,
        feed_id: str,
        domains: Sequence[Tuple[str, Optional[str]]],
        upload_type: str = "INCREMENTAL",
    ) -> int:
        """Upload (domain, action) pairs as CSV. Returns the number of rows sent."""
        csv_text = build_csv(domains, upload_type)
        self._request(
            "POST",
            f"/threat-feeds/{feed_id}/elements?uploadType={upload_type}",
            files={"file": ("domains.csv", csv_text.encode("utf-8"), "text/csv")},
        )
        return len(domains)

    def preview_changes(self, feed_id: str, desired: Sequence[str]) -> DomainDiff:
        """Diff a desired final domain list against the live feed contents."""
        current = self.get_domains(feed_id)
        added, removed, unchanged = diff_domains(current, desired)
        return DomainDiff(
            current_count=len(current), added=added, removed=removed, unchanged=unchanged
        )

    # ── Remote source downloads ─────────────────────────────────────────────

    def download_domains(self, source_url: str, verify_ssl: bool = True) -> List[str]:
        """Download a remote feed and extract valid domains from its content."""
        parsed = urlparse(source_url)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(f"invalid URL scheme '{parsed.scheme}' — only http/https allowed")
        if not verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        try:
            r = self.session.get(source_url, verify=verify_ssl, timeout=self._timeout)
        except requests.RequestException as e:
            raise ThreatFeedError(f"download from {source_url} failed: {e}") from e
        if r.status_code != 200:
            raise ThreatFeedError(
                f"download from {source_url} failed: HTTP {r.status_code}",
                status=r.status_code,
            )
        return extract_domains_from_text(r.text)

    def update_from_url(
        self,
        feed_id: str,
        source_url: str,
        upload_type: str = "OVERWRITE",
        verify_ssl: bool = True,
    ) -> int:
        """Download domains from source_url and upload them. Returns rows uploaded."""
        domains = self.download_domains(source_url, verify_ssl)
        if not domains:
            raise ThreatFeedError(f"no valid domains found in content from {source_url}")
        action = "add" if upload_type == "INCREMENTAL" else None
        return self.upload_domains(feed_id, [(d, action) for d in domains], upload_type)
