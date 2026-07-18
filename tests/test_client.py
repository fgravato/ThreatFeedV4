"""Tests for threatfeed.client — HTTP fully mocked with the responses library."""

import pytest
import responses

from threatfeed import config
from threatfeed.client import (
    AuthenticationError,
    ThreatFeedClient,
    ThreatFeedError,
)

API = config.BASE_URL
TOKEN_URL = config.TOKEN_URL
FEED_ID = "abc123-feed-id"


def add_token(token="test-token"):
    responses.add(responses.POST, TOKEN_URL, json={"access_token": token}, status=200)


@pytest.fixture
def client():
    return ThreatFeedClient("fake-api-key")


# ── Authentication ──────────────────────────────────────────────────────────


@responses.activate
def test_token_fetched_lazily_and_cached(client):
    add_token()
    responses.add(responses.GET, f"{API}/threat-feeds", json=["f1"], status=200)
    assert client.list_feed_ids() == ["f1"]
    assert client.token == "test-token"
    token_calls = [c for c in responses.calls if c.request.url == TOKEN_URL]
    assert len(token_calls) == 1


@responses.activate
def test_token_request_failure_raises_auth_error(client):
    responses.add(responses.POST, TOKEN_URL, json={"detail": "invalid key"}, status=403)
    with pytest.raises(AuthenticationError, match="invalid key"):
        client.list_feed_ids()


@responses.activate
def test_token_missing_from_response(client):
    responses.add(responses.POST, TOKEN_URL, json={"nope": 1}, status=200)
    with pytest.raises(AuthenticationError, match="access_token"):
        client.list_feed_ids()


@responses.activate
def test_401_triggers_single_token_refresh_and_retry(client):
    add_token("stale-token")
    add_token("fresh-token")
    responses.add(responses.GET, f"{API}/threat-feeds", json={"detail": "expired"}, status=401)
    responses.add(responses.GET, f"{API}/threat-feeds", json=["f1", "f2"], status=200)

    assert client.list_feed_ids() == ["f1", "f2"]
    token_calls = [c for c in responses.calls if c.request.url == TOKEN_URL]
    assert len(token_calls) == 2
    # The retry must have used the fresh token.
    get_calls = [c for c in responses.calls if c.request.url == f"{API}/threat-feeds"]
    assert get_calls[-1].request.headers["Authorization"] == "Bearer fresh-token"


@responses.activate
def test_repeated_401_does_not_loop(client):
    add_token()
    add_token()
    responses.add(responses.GET, f"{API}/threat-feeds", status=401)
    responses.add(responses.GET, f"{API}/threat-feeds", status=401)
    with pytest.raises(ThreatFeedError) as exc_info:
        client.list_feed_ids()
    assert exc_info.value.status == 401


# ── Error handling ──────────────────────────────────────────────────────────


@responses.activate
def test_error_detail_extracted_from_body(client):
    add_token()
    responses.add(
        responses.GET,
        f"{API}/threat-feeds/{FEED_ID}",
        json={"detail": "feed not found"},
        status=404,
    )
    with pytest.raises(ThreatFeedError, match="feed not found") as exc_info:
        client.get_feed_metadata(FEED_ID)
    assert exc_info.value.status == 404


@responses.activate
def test_error_detail_falls_back_to_text(client):
    add_token()
    responses.add(
        responses.GET, f"{API}/threat-feeds/{FEED_ID}", body="upstream broke", status=500
    )
    with pytest.raises(ThreatFeedError, match="upstream broke"):
        client.get_feed_metadata(FEED_ID)


def test_retry_adapter_configuration(client):
    adapter = client.session.get_adapter("https://example.com")
    retries = adapter.max_retries
    assert retries.total == 3
    assert 429 in retries.status_forcelist
    assert retries.backoff_factor > 0


# ── Feed operations ─────────────────────────────────────────────────────────


@responses.activate
def test_list_feeds_fetches_metadata_in_parallel(client):
    add_token()
    responses.add(responses.GET, f"{API}/threat-feeds", json=["f1", "f2"], status=200)
    responses.add(
        responses.GET, f"{API}/threat-feeds/f1",
        json={"title": "Feed One", "elementsCount": 10}, status=200,
    )
    responses.add(
        responses.GET, f"{API}/threat-feeds/f2",
        json={"title": "Feed Two", "elementsCount": 20}, status=200,
    )
    feeds = client.list_feeds()
    assert {f["feedId"] for f in feeds} == {"f1", "f2"}
    assert {f["title"] for f in feeds} == {"Feed One", "Feed Two"}


@responses.activate
def test_list_feeds_tolerates_single_metadata_failure(client):
    add_token()
    responses.add(responses.GET, f"{API}/threat-feeds", json=["f1", "f2"], status=200)
    responses.add(responses.GET, f"{API}/threat-feeds/f1", json={"title": "OK"}, status=200)
    responses.add(responses.GET, f"{API}/threat-feeds/f2", status=500)
    feeds = client.list_feeds()
    by_id = {f["feedId"]: f for f in feeds}
    assert by_id["f1"]["title"] == "OK"
    assert "error" in by_id["f2"]


@responses.activate
def test_create_feed_success(client):
    add_token()
    responses.add(
        responses.POST, f"{API}/threat-feeds", json={"feedId": "new-id"}, status=200
    )
    feed_id = client.create_feed("My Feed Title", "A description here")
    assert feed_id == "new-id"
    body = responses.calls[-1].request.body
    assert b'"feedType": "CSV"' in body


def test_create_feed_validates_lengths(client):
    with pytest.raises(ValueError, match="Title must be"):
        client.create_feed("short", "A description here")
    with pytest.raises(ValueError, match="Description must be"):
        client.create_feed("A valid title", "short")


@responses.activate
def test_delete_feed(client):
    add_token()
    responses.add(responses.DELETE, f"{API}/threat-feeds/{FEED_ID}", status=204)
    client.delete_feed(FEED_ID)  # no exception == success


# ── Domain operations ───────────────────────────────────────────────────────


@responses.activate
def test_get_domains_parses_csv(client):
    add_token()
    responses.add(
        responses.GET,
        f"{API}/threat-feeds/{FEED_ID}/elements",
        body="domain\r\nevil.com\r\nbad.io\r\n",
        status=200,
    )
    assert client.get_domains(FEED_ID) == ["evil.com", "bad.io"]


@responses.activate
def test_upload_incremental_payload_shape(client):
    add_token()
    responses.add(responses.POST, f"{API}/threat-feeds/{FEED_ID}/elements", status=200)
    count = client.upload_domains(
        FEED_ID, [("evil.com", "add"), ("old.com", "delete")], "INCREMENTAL"
    )
    assert count == 2
    request = responses.calls[-1].request
    assert "uploadType=INCREMENTAL" in request.url
    body = request.body
    if isinstance(body, str):
        body = body.encode()
    assert b"multipart/form-data" in request.headers["Content-Type"].encode()
    assert b"domain,action" in body
    assert b"evil.com,add" in body
    assert b"old.com,delete" in body


@responses.activate
def test_upload_overwrite_payload_shape(client):
    add_token()
    responses.add(responses.POST, f"{API}/threat-feeds/{FEED_ID}/elements", status=200)
    client.upload_domains(FEED_ID, [("evil.com", None)], "OVERWRITE")
    request = responses.calls[-1].request
    assert "uploadType=OVERWRITE" in request.url
    body = request.body
    if isinstance(body, str):
        body = body.encode()
    assert b"evil.com" in body
    assert b",add" not in body


@responses.activate
def test_preview_changes(client):
    add_token()
    responses.add(
        responses.GET,
        f"{API}/threat-feeds/{FEED_ID}/elements",
        body="domain\na.com\nb.com\n",
        status=200,
    )
    diff = client.preview_changes(FEED_ID, ["b.com", "c.com"])
    assert diff.current_count == 2
    assert diff.added == ["c.com"]
    assert diff.removed == ["a.com"]
    assert diff.unchanged == ["b.com"]
    assert diff.changed


# ── URL downloads ───────────────────────────────────────────────────────────


@responses.activate
def test_download_domains_extracts_hostnames(client):
    responses.add(
        responses.GET,
        "https://intel.example.com/feed.txt",
        body="# comment\nhttps://evil.com/path\nbad.io\nnot a domain\n",
        status=200,
    )
    assert client.download_domains("https://intel.example.com/feed.txt") == [
        "evil.com",
        "bad.io",
    ]


def test_download_domains_rejects_bad_scheme(client):
    with pytest.raises(ValueError, match="scheme"):
        client.download_domains("ftp://example.com/feed.txt")


@responses.activate
def test_download_domains_http_error(client):
    responses.add(responses.GET, "https://intel.example.com/feed.txt", status=404)
    with pytest.raises(ThreatFeedError, match="HTTP 404"):
        client.download_domains("https://intel.example.com/feed.txt")


@responses.activate
def test_update_from_url_end_to_end(client):
    add_token()
    responses.add(
        responses.GET, "https://intel.example.com/feed.txt",
        body="evil.com\nhttps://bad.io/x\n", status=200,
    )
    responses.add(responses.POST, f"{API}/threat-feeds/{FEED_ID}/elements", status=200)
    count = client.update_from_url(FEED_ID, "https://intel.example.com/feed.txt")
    assert count == 2
    upload = responses.calls[-1].request
    assert "uploadType=OVERWRITE" in upload.url


@responses.activate
def test_update_from_url_empty_source(client):
    add_token()
    responses.add(
        responses.GET, "https://intel.example.com/feed.txt", body="# nothing here", status=200
    )
    with pytest.raises(ThreatFeedError, match="no valid domains"):
        client.update_from_url(FEED_ID, "https://intel.example.com/feed.txt")
