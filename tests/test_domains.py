"""Tests for threatfeed.domains — pure logic, no network."""

from threatfeed.domains import (
    build_csv,
    diff_domains,
    extract_domains_from_text,
    is_valid_domain,
    normalize_domain,
    parse_domain_lines,
    parse_elements_csv,
)


class TestNormalize:
    def test_lowercases(self):
        assert normalize_domain("EVIL.COM") == "evil.com"

    def test_strips_whitespace(self):
        assert normalize_domain("  evil.com  ") == "evil.com"

    def test_strips_trailing_dot(self):
        assert normalize_domain("evil.com.") == "evil.com"

    def test_strips_whitespace_then_dot(self):
        assert normalize_domain("  Evil.Com. ") == "evil.com"


class TestValidation:
    def test_valid_domains(self):
        for d in ("evil.com", "phishing.net", "bad-actor.io", "a.b.co.uk", "x9.example.museum"):
            assert is_valid_domain(d), d

    def test_valid_after_normalization(self):
        assert is_valid_domain("  EVIL.com. ")

    def test_rejects_ip_addresses(self):
        assert not is_valid_domain("192.168.1.1")

    def test_rejects_bare_hostname(self):
        assert not is_valid_domain("localhost")

    def test_rejects_spaces(self):
        assert not is_valid_domain("evil domain.com")

    def test_rejects_leading_hyphen_label(self):
        assert not is_valid_domain("-evil.com")

    def test_rejects_numeric_tld(self):
        assert not is_valid_domain("evil.123")

    def test_rejects_single_char_tld(self):
        assert not is_valid_domain("evil.c")

    def test_rejects_empty(self):
        assert not is_valid_domain("   ")


class TestParseDomainLines:
    def test_skips_comments_and_blanks(self):
        valid, invalid = parse_domain_lines([
            "# comment",
            "",
            "   ",
            "evil.com",
            "# disabled: phishing.net",
            "bad-actor.io",
        ])
        assert valid == ["evil.com", "bad-actor.io"]
        assert invalid == []

    def test_normalizes_and_dedups_preserving_order(self):
        valid, _ = parse_domain_lines([
            "B.com",
            "a.com",
            "b.com",
            "  A.COM. ",
        ])
        assert valid == ["b.com", "a.com"]

    def test_collects_invalid_entries(self):
        valid, invalid = parse_domain_lines(["evil.com", "not a domain", "192.168.1.1"])
        assert valid == ["evil.com"]
        assert invalid == ["not a domain", "192.168.1.1"]

    def test_empty_input(self):
        assert parse_domain_lines([]) == ([], [])


class TestBuildCsv:
    def test_incremental_includes_actions(self):
        csv_text = build_csv(
            [("evil.com", "add"), ("old.com", "delete")], "INCREMENTAL"
        )
        assert csv_text == "domain,action\nevil.com,add\nold.com,delete\n"

    def test_overwrite_domain_only(self):
        csv_text = build_csv([("evil.com", None), ("bad.io", None)], "OVERWRITE")
        assert csv_text == "domain\nevil.com\nbad.io\n"

    def test_no_trailing_blank_line(self):
        csv_text = build_csv([("evil.com", "add")], "INCREMENTAL")
        assert not csv_text.endswith("\n\n")


class TestParseElementsCsv:
    def test_skips_header(self):
        assert parse_elements_csv("domain\nevil.com\nbad.io\n") == ["evil.com", "bad.io"]

    def test_tolerates_crlf(self):
        assert parse_elements_csv("domain\r\nevil.com\r\n") == ["evil.com"]

    def test_tolerates_missing_header(self):
        assert parse_elements_csv("evil.com\nbad.io\n") == ["evil.com", "bad.io"]

    def test_empty_response(self):
        assert parse_elements_csv("") == []

    def test_header_only(self):
        assert parse_elements_csv("domain\n") == []


class TestExtractDomainsFromText:
    def test_plain_domains(self):
        assert extract_domains_from_text("evil.com\nbad.io\n") == ["evil.com", "bad.io"]

    def test_urls_reduce_to_hostname(self):
        text = "https://evil.com/path?q=1\nhttp://bad.io:8080/x"
        assert extract_domains_from_text(text) == ["evil.com", "bad.io"]

    def test_skips_comments_blanks_and_garbage(self):
        text = "# comment\n\nevil.com\nnot a domain\n"
        assert extract_domains_from_text(text) == ["evil.com"]

    def test_dedups_across_forms(self):
        text = "evil.com\nhttps://EVIL.com/page\nhttps://evil.com:443/other"
        assert extract_domains_from_text(text) == ["evil.com"]

    def test_empty(self):
        assert extract_domains_from_text("") == []


class TestDiffDomains:
    def test_added_removed_unchanged(self):
        added, removed, unchanged = diff_domains(
            ["a.com", "b.com", "c.com"],
            ["b.com", "c.com", "d.com"],
        )
        assert added == ["d.com"]
        assert removed == ["a.com"]
        assert unchanged == ["b.com", "c.com"]

    def test_normalizes_before_comparing(self):
        added, removed, unchanged = diff_domains(["Evil.com"], ["evil.COM."])
        assert added == removed == []
        assert unchanged == ["evil.com"]

    def test_full_replacement(self):
        added, removed, unchanged = diff_domains(["a.com"], ["b.com"])
        assert added == ["b.com"]
        assert removed == ["a.com"]
        assert unchanged == []

    def test_noop(self):
        added, removed, unchanged = diff_domains(["a.com"], ["a.com"])
        assert added == removed == []
        assert unchanged == ["a.com"]
