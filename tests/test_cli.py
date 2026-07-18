"""Tests for threatfeed.cli — HTTP mocked; verifies parsing, dispatch, and exit codes."""

import json

import pytest
import responses

from threatfeed import cli, config
from threatfeed.cli import main

API = config.BASE_URL
FEED_ID = "feed-123"


@pytest.fixture(autouse=True)
def api_key_env(monkeypatch):
    monkeypatch.setenv(config.API_KEY_ENV_VAR, "fake-api-key")


def add_token():
    responses.add(responses.POST, config.TOKEN_URL, json={"access_token": "tok"}, status=200)


def add_elements(domains):
    body = "domain\n" + "".join(f"{d}\n" for d in domains)
    responses.add(responses.GET, f"{API}/threat-feeds/{FEED_ID}/elements",
                  body=body, status=200)


def request_bodies():
    return [c.request for c in responses.calls]


# ── Basics ────────────────────────────────────────────────────────────────────


def test_version(capsys):
    assert main(["--version"]) == 0
    assert "threatfeed" in capsys.readouterr().out


def test_missing_api_key(monkeypatch, capsys):
    monkeypatch.setattr(config, "load_api_key", lambda: None)
    assert main(["list"]) == 1
    assert "LOOKOUT_API_KEY" in capsys.readouterr().err


@responses.activate
def test_api_error_returns_exit_1(capsys):
    add_token()
    responses.add(responses.GET, f"{API}/threat-feeds", json={"detail": "boom"}, status=500)
    assert main(["list"]) == 1
    assert "boom" in capsys.readouterr().err


# ── list / view / create ──────────────────────────────────────────────────────


@responses.activate
def test_list_table(capsys):
    add_token()
    responses.add(responses.GET, f"{API}/threat-feeds", json=[FEED_ID], status=200)
    responses.add(responses.GET, f"{API}/threat-feeds/{FEED_ID}",
                  json={"title": "My Feed", "elementsCount": 3,
                        "elementsUploadedAt": "2026-07-01T10:00:00Z"}, status=200)
    assert main(["list"]) == 0
    out = capsys.readouterr().out
    assert "My Feed" in out and FEED_ID in out


@responses.activate
def test_list_json(capsys):
    add_token()
    responses.add(responses.GET, f"{API}/threat-feeds", json=[FEED_ID], status=200)
    responses.add(responses.GET, f"{API}/threat-feeds/{FEED_ID}",
                  json={"title": "My Feed"}, status=200)
    assert main(["--json", "list"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data[0]["feedId"] == FEED_ID


@responses.activate
def test_legacy_list_feeds_matches_list(capsys):
    add_token()
    responses.add(responses.GET, f"{API}/threat-feeds", json=[FEED_ID], status=200)
    responses.add(responses.GET, f"{API}/threat-feeds/{FEED_ID}",
                  json={"title": "Legacy Feed"}, status=200)
    assert main(["--list-feeds"]) == 0
    assert "Legacy Feed" in capsys.readouterr().out


@responses.activate
def test_view_prints_metadata_json(capsys):
    add_token()
    responses.add(responses.GET, f"{API}/threat-feeds/{FEED_ID}",
                  json={"title": "X", "feedType": "CSV"}, status=200)
    assert main(["view", FEED_ID]) == 0
    assert json.loads(capsys.readouterr().out)["feedType"] == "CSV"


@responses.activate
def test_create(capsys):
    add_token()
    responses.add(responses.POST, f"{API}/threat-feeds", json={"feedId": "new-1"}, status=200)
    assert main(["create", "A valid title", "A valid description"]) == 0
    assert "new-1" in capsys.readouterr().out


def test_create_rejects_short_title():
    assert main(["create", "short", "A valid description"]) == 1


# ── delete ────────────────────────────────────────────────────────────────────


@responses.activate
def test_delete_with_yes_flag(capsys):
    add_token()
    responses.add(responses.DELETE, f"{API}/threat-feeds/{FEED_ID}", status=204)
    assert main(["delete", FEED_ID, "-y"]) == 0
    assert "deleted" in capsys.readouterr().out


@responses.activate
def test_delete_prompt_declined_makes_no_request(monkeypatch, capsys):
    add_token()
    monkeypatch.setattr("builtins.input", lambda prompt="": "no")
    assert main(["delete", FEED_ID]) == 0
    assert "Cancelled" in capsys.readouterr().out
    assert len(responses.calls) == 0


@responses.activate
def test_delete_prompt_confirmed(monkeypatch):
    add_token()
    responses.add(responses.DELETE, f"{API}/threat-feeds/{FEED_ID}", status=204)
    monkeypatch.setattr("builtins.input", lambda prompt="": "yes")
    assert main(["delete", FEED_ID]) == 0


@responses.activate
def test_legacy_delete_feed_skips_prompt():
    # No input mock: a prompt would raise OSError under pytest and fail the test.
    add_token()
    responses.add(responses.DELETE, f"{API}/threat-feeds/{FEED_ID}", status=204)
    assert main(["--delete-feed", FEED_ID]) == 0


# ── add / remove ──────────────────────────────────────────────────────────────


@responses.activate
def test_add_domains(capsys):
    add_token()
    responses.add(responses.POST, f"{API}/threat-feeds/{FEED_ID}/elements", status=200)
    assert main(["add", FEED_ID, "evil.com", "BAD.io"]) == 0
    out = capsys.readouterr().out
    assert "Added 2 domain(s)" in out
    body = request_bodies()[-1].body
    if isinstance(body, str):
        body = body.encode()
    assert b"evil.com,add" in body and b"bad.io,add" in body  # normalized


@responses.activate
def test_add_dry_run_uploads_nothing(capsys):
    add_token()
    add_elements(["existing.com"])
    assert main(["add", FEED_ID, "new.com", "existing.com", "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "+ 1 to add" in out
    assert "Dry run" in out
    methods = [r.method for r in request_bodies()]
    assert "POST" not in methods or all(
        "oauth2" in r.url for r in request_bodies() if r.method == "POST"
    )


@responses.activate
def test_add_from_file(tmp_path, capsys):
    add_token()
    responses.add(responses.POST, f"{API}/threat-feeds/{FEED_ID}/elements", status=200)
    f = tmp_path / "domains.txt"
    f.write_text("# comment\nevil.com\nbad.io\n")
    assert main(["add", FEED_ID, "--file", str(f)]) == 0
    assert "Added 2 domain(s)" in capsys.readouterr().out


@responses.activate
def test_remove_prompts_and_uploads_only_present(monkeypatch, capsys):
    add_token()
    add_elements(["evil.com", "keep.com"])
    responses.add(responses.POST, f"{API}/threat-feeds/{FEED_ID}/elements", status=200)
    monkeypatch.setattr("builtins.input", lambda prompt="": "yes")
    assert main(["remove", FEED_ID, "evil.com", "nothere.com"]) == 0
    out = capsys.readouterr().out
    assert "Removed 1 domain(s)" in out
    body = request_bodies()[-1].body
    if isinstance(body, str):
        body = body.encode()
    assert b"evil.com,delete" in body
    assert b"nothere.com" not in body


@responses.activate
def test_remove_declined(capsys, monkeypatch):
    add_token()
    add_elements(["evil.com"])
    monkeypatch.setattr("builtins.input", lambda prompt="": "no")
    assert main(["remove", FEED_ID, "evil.com"]) == 0
    assert "Cancelled" in capsys.readouterr().out


@responses.activate
def test_legacy_remove_domain_skips_prompt(capsys):
    add_token()
    add_elements(["evil.com"])
    responses.add(responses.POST, f"{API}/threat-feeds/{FEED_ID}/elements", status=200)
    assert main(["--remove-domain", FEED_ID, "evil.com"]) == 0
    assert "Removed 1 domain(s)" in capsys.readouterr().out


# ── update ────────────────────────────────────────────────────────────────────


@responses.activate
def test_update_overwrite_prompts(monkeypatch, capsys):
    add_token()
    responses.add(responses.GET, "https://intel.example.com/feed.txt",
                  body="new1.com\nnew2.com\n", status=200)
    add_elements(["old.com"])
    responses.add(responses.POST, f"{API}/threat-feeds/{FEED_ID}/elements", status=200)
    monkeypatch.setattr("builtins.input", lambda prompt="": "yes")
    assert main(["update", FEED_ID, "https://intel.example.com/feed.txt"]) == 0
    out = capsys.readouterr().out
    assert "+ 2 to add" in out and "- 1 to remove" in out
    upload = request_bodies()[-1]
    assert "uploadType=OVERWRITE" in upload.url


@responses.activate
def test_update_overwrite_declined_uploads_nothing(capsys, monkeypatch):
    add_token()
    responses.add(responses.GET, "https://intel.example.com/feed.txt",
                  body="new1.com\n", status=200)
    add_elements(["old.com"])
    monkeypatch.setattr("builtins.input", lambda prompt="": "no")
    assert main(["update", FEED_ID, "https://intel.example.com/feed.txt"]) == 0
    assert "Cancelled" in capsys.readouterr().out


@responses.activate
def test_update_incremental_does_not_prompt(capsys):
    add_token()
    responses.add(responses.GET, "https://intel.example.com/feed.txt",
                  body="new1.com\n", status=200)
    add_elements(["old.com"])
    responses.add(responses.POST, f"{API}/threat-feeds/{FEED_ID}/elements", status=200)
    assert main(["update", FEED_ID, "https://intel.example.com/feed.txt",
                 "--upload-type", "INCREMENTAL"]) == 0
    assert "uploadType=INCREMENTAL" in request_bodies()[-1].url


@responses.activate
def test_update_dry_run(capsys):
    add_token()
    responses.add(responses.GET, "https://intel.example.com/feed.txt",
                  body="new1.com\n", status=200)
    add_elements(["old.com"])
    assert main(["update", FEED_ID, "https://intel.example.com/feed.txt", "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "Dry run" in out
    assert all("elements" not in r.url or r.method == "GET" for r in request_bodies())


@responses.activate
def test_legacy_update_feed_flags():
    add_token()
    responses.add(responses.GET, "https://intel.example.com/feed.txt",
                  body="new1.com\n", status=200)
    add_elements(["old.com"])
    responses.add(responses.POST, f"{API}/threat-feeds/{FEED_ID}/elements", status=200)
    assert main(["--update-feed", FEED_ID, "https://intel.example.com/feed.txt",
                 "--upload-type", "INCREMENTAL"]) == 0
    assert "uploadType=INCREMENTAL" in request_bodies()[-1].url


# ── export / search ───────────────────────────────────────────────────────────


@responses.activate
def test_export_to_file(tmp_path, capsys):
    add_token()
    add_elements(["evil.com", "bad.io"])
    out_file = tmp_path / "backup.txt"
    assert main(["export", FEED_ID, "-o", str(out_file)]) == 0
    assert out_file.read_text() == "evil.com\nbad.io\n"
    assert "Exported 2 domain(s)" in capsys.readouterr().out


@responses.activate
def test_export_to_stdout(capsys):
    add_token()
    add_elements(["evil.com"])
    assert main(["export", FEED_ID]) == 0
    assert capsys.readouterr().out.strip() == "evil.com"


@responses.activate
def test_search(capsys):
    add_token()
    add_elements(["evil.com", "evil2.com", "good.com"])
    assert main(["search", FEED_ID, "evil"]) == 0
    out = capsys.readouterr().out
    assert "evil.com" in out and "evil2.com" in out and "good.com" not in out
    assert "2 of 3" in out


@responses.activate
def test_search_json(capsys):
    add_token()
    add_elements(["evil.com", "good.com"])
    assert main(["--json", "search", FEED_ID, "evil"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["matches"] == ["evil.com"]


# ── gather helper ─────────────────────────────────────────────────────────────


def test_gather_domains_merges_sources(tmp_path, capsys):
    f = tmp_path / "d.txt"
    f.write_text("fromfile.com\n# ignored\n")
    result = cli._gather_domains(["inline.com", "bad domain"], str(f))
    assert result == ["inline.com", "fromfile.com"]
    assert "skipped 1 invalid" in capsys.readouterr().err
