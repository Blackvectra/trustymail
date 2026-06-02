"""Tests for the trustymail module."""

# Standard Python Libraries
import unittest
from unittest import mock

# Third-Party Libraries
import dns.resolver
import pytest

# cisagov Libraries
import trustymail.domain as trustymail_domain
from trustymail.domain import Domain, format_list
import trustymail.trustymail as trustymail


class _FakeRecord:
    """A minimal stand-in for a dnspython answer record."""

    def __init__(self, text):
        """Store the textual representation of the record."""
        self._text = text

    def to_text(self):
        """Return the textual representation of the record."""
        return self._text


class _FakeResolver:
    """A minimal stand-in for dns.resolver.Resolver.

    It returns canned TXT records for known names and raises NXDOMAIN
    for everything else.
    """

    def __init__(self, txt_by_name=None):
        """Store the mapping of query names to record text."""
        self._txt_by_name = txt_by_name or {}

    def query(self, name, rdtype, tcp=True):
        """Return the canned records for name, or raise NXDOMAIN."""
        if name in self._txt_by_name:
            return [_FakeRecord(text) for text in self._txt_by_name[name]]
        raise dns.resolver.NXDOMAIN()


class _FakeResponse:
    """A minimal stand-in for a requests.Response object."""

    def __init__(self, status_code=200, text=""):
        """Store the status code and body text."""
        self.status_code = status_code
        self.text = text


def _make_domain(name="example.com"):
    """Build a Domain without performing any network lookups.

    The public suffix lookup is stubbed so that the domain is treated
    as its own base domain, which avoids both the PSL download and the
    recursive DMARC scan of a parent domain.
    """
    with mock.patch.object(trustymail_domain, "get_public_suffix", return_value=name):
        return Domain(name, 5, 5, None, {25}, True, None)


class TestDomainListParsing(unittest.TestCase):
    """Test parsing of domain lists from CSV input."""

    def test_domain_list_parsing_with_header(self):
        """A column whose header contains 'domain' is used and the header dropped."""
        csv_lines = [
            "Agency,Domain",
            "Test Agency,example.com",
            "Other Agency,example.org",
        ]
        self.assertEqual(
            trustymail.domain_list_from_csv(csv_lines),
            ["example.com", "example.org"],
        )

    def test_domain_list_parsing_without_header(self):
        """With no 'domain' header the first column is used and no row dropped."""
        csv_lines = ["example.com", "example.org"]
        self.assertEqual(
            trustymail.domain_list_from_csv(csv_lines),
            ["example.com", "example.org"],
        )


class TestUtilityFunctions(unittest.TestCase):
    """Test the small pure helper functions."""

    def test_remove_quotes_single_string(self):
        """Surrounding double quotes are stripped from a TXT record."""
        self.assertEqual(trustymail.remove_quotes('"v=spf1 -all"'), "v=spf1 -all")

    def test_remove_quotes_concatenates_multiple_strings(self):
        """Adjacent quoted strings in a TXT record are concatenated."""
        self.assertEqual(trustymail.remove_quotes('"v=spf1 " "-all"'), "v=spf1 -all")

    def test_format_list_empty_is_none(self):
        """An empty list is rendered as None for the output."""
        self.assertIsNone(format_list([]))

    def test_format_list_joins_with_commas(self):
        """A populated list is rendered as a comma-separated string."""
        self.assertEqual(format_list(["a", "b", "c"]), "a, b, c")

    def test_parse_semicolon_tags(self):
        """A semicolon-delimited record is parsed into a tag dictionary."""
        self.assertEqual(
            trustymail.parse_semicolon_tags("v=STSv1; id=20230101T000000"),
            {"v": "STSv1", "id": "20230101T000000"},
        )

    def test_parse_semicolon_tags_ignores_valueless_options(self):
        """Options without an equals sign are ignored."""
        self.assertEqual(
            trustymail.parse_semicolon_tags("v=TLSRPTv1; ; rua=mailto:a@b.com"),
            {"v": "TLSRPTv1", "rua": "mailto:a@b.com"},
        )

    def test_parse_dmarc_report_uri_without_size_limit(self):
        """A bare mailto URI is parsed with no size limit."""
        parsed = trustymail.parse_dmarc_report_uri("mailto:reports@example.com")
        self.assertEqual(parsed["scheme"], "mailto")
        self.assertEqual(parsed["address"], "reports@example.com")
        self.assertIsNone(parsed["size_limit"])

    def test_parse_dmarc_report_uri_with_size_limit(self):
        """A mailto URI with a size limit is parsed correctly."""
        parsed = trustymail.parse_dmarc_report_uri("mailto:reports@example.com!10m")
        self.assertEqual(parsed["size_limit"], "10m")

    def test_parse_dmarc_report_uri_invalid(self):
        """A non-mailto URI returns None."""
        self.assertIsNone(trustymail.parse_dmarc_report_uri("https://example.com"))


class TestFetchMtaStsPolicy(unittest.TestCase):
    """Test fetching and validating an MTA-STS policy file."""

    def setUp(self):
        """Create a domain with MTA-STS state initialized to valid."""
        self.domain = _make_domain()
        # fetch_mta_sts_policy is normally called after the DNS record
        # check has tentatively marked the policy valid.
        self.domain.valid_mta_sts = True

    def _fetch(self, response=None, side_effect=None):
        kwargs = {}
        if side_effect is not None:
            kwargs["side_effect"] = side_effect
        else:
            kwargs["return_value"] = response
        with mock.patch.object(trustymail.requests, "get", **kwargs):
            trustymail.fetch_mta_sts_policy(self.domain, 5)

    def test_valid_enforce_policy(self):
        """A well-formed enforce policy is parsed and remains valid."""
        policy = (
            "version: STSv1\n"
            "mode: enforce\n"
            "mx: mail.example.com\n"
            "mx: *.example.net\n"
            "max_age: 604800\n"
        )
        self._fetch(_FakeResponse(200, policy))
        self.assertTrue(self.domain.valid_mta_sts)
        self.assertEqual(self.domain.mta_sts_policy_mode, "enforce")
        self.assertEqual(
            self.domain.mta_sts_policy_mx, ["mail.example.com", "*.example.net"]
        )
        self.assertEqual(self.domain.mta_sts_policy_max_age, 604800)

    def test_invalid_mode_is_rejected(self):
        """An unknown mode marks the policy invalid."""
        policy = "version: STSv1\nmode: bogus\nmx: m.example.com\nmax_age: 86400\n"
        self._fetch(_FakeResponse(200, policy))
        self.assertFalse(self.domain.valid_mta_sts)

    def test_missing_max_age_is_rejected(self):
        """A policy without max_age is invalid."""
        policy = "version: STSv1\nmode: enforce\nmx: m.example.com\n"
        self._fetch(_FakeResponse(200, policy))
        self.assertFalse(self.domain.valid_mta_sts)

    def test_max_age_out_of_range_is_rejected(self):
        """A max_age above the allowed limit is invalid."""
        policy = (
            "version: STSv1\n"
            "mode: enforce\n"
            "mx: m.example.com\n"
            "max_age: 999999999999\n"
        )
        self._fetch(_FakeResponse(200, policy))
        self.assertFalse(self.domain.valid_mta_sts)

    def test_non_integer_max_age_is_rejected(self):
        """A non-integer max_age is invalid."""
        policy = "version: STSv1\nmode: enforce\nmx: m.example.com\nmax_age: soon\n"
        self._fetch(_FakeResponse(200, policy))
        self.assertFalse(self.domain.valid_mta_sts)

    def test_enforce_without_mx_is_rejected(self):
        """An enforce/testing policy must list at least one mx host."""
        policy = "version: STSv1\nmode: enforce\nmax_age: 86400\n"
        self._fetch(_FakeResponse(200, policy))
        self.assertFalse(self.domain.valid_mta_sts)

    def test_http_error_status_is_rejected(self):
        """A non-200 HTTP response marks the policy invalid."""
        self._fetch(_FakeResponse(404, ""))
        self.assertFalse(self.domain.valid_mta_sts)

    def test_request_exception_is_handled(self):
        """A network error is recorded and marks the policy invalid."""
        self._fetch(side_effect=trustymail.requests.RequestException("boom"))
        self.assertFalse(self.domain.valid_mta_sts)
        self.assertTrue(
            any("Unable to retrieve" in info for info in self.domain.debug_info)
        )


class TestMtaStsScan(unittest.TestCase):
    """Test the MTA-STS DNS record scan."""

    def setUp(self):
        """Create a domain to scan."""
        self.domain = _make_domain()

    def _scan(self, resolver, policy_response=None):
        with mock.patch.object(
            trustymail, "check_dnssec", return_value=True
        ), mock.patch.object(
            trustymail.requests,
            "get",
            return_value=policy_response or _FakeResponse(200, ""),
        ):
            trustymail.mta_sts_scan(resolver, self.domain, 5)

    def test_present_and_valid(self):
        """A valid record plus enforce policy yields valid_mta_sts True."""
        resolver = _FakeResolver(
            {"_mta-sts.example.com": ['"v=STSv1; id=20230101T000000Z"']}
        )
        policy = "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 86400\n"
        self._scan(resolver, _FakeResponse(200, policy))
        self.assertTrue(self.domain.has_mta_sts_record)
        self.assertTrue(self.domain.valid_mta_sts)
        self.assertEqual(self.domain.mta_sts_policy_mode, "enforce")

    def test_missing_id_tag_is_invalid(self):
        """A record without an id tag is invalid."""
        resolver = _FakeResolver({"_mta-sts.example.com": ['"v=STSv1;"']})
        self._scan(resolver)
        self.assertTrue(self.domain.has_mta_sts_record)
        self.assertFalse(self.domain.valid_mta_sts)

    def test_malformed_id_tag_is_invalid(self):
        """An id tag with illegal characters is invalid."""
        resolver = _FakeResolver({"_mta-sts.example.com": ['"v=STSv1; id=has spaces"']})
        self._scan(resolver)
        self.assertFalse(self.domain.valid_mta_sts)

    def test_multiple_records_is_invalid(self):
        """Multiple MTA-STS records are an error."""
        resolver = _FakeResolver(
            {"_mta-sts.example.com": ['"v=STSv1; id=a"', '"v=STSv1; id=b"']}
        )
        self._scan(resolver)
        self.assertTrue(self.domain.has_mta_sts_record)
        self.assertFalse(self.domain.valid_mta_sts)

    def test_absent_record(self):
        """A domain with no record reports has_mta_sts_record False."""
        self._scan(_FakeResolver({}))
        self.assertFalse(self.domain.has_mta_sts_record)
        self.assertFalse(self.domain.valid_mta_sts)


class TestTlsRptScan(unittest.TestCase):
    """Test the TLS-RPT DNS record scan."""

    def setUp(self):
        """Create a domain to scan."""
        self.domain = _make_domain()

    def _scan(self, resolver):
        with mock.patch.object(trustymail, "check_dnssec", return_value=True):
            trustymail.tls_rpt_scan(resolver, self.domain)

    def test_present_and_valid(self):
        """A record with valid rua URIs yields valid_tlsrpt True."""
        resolver = _FakeResolver(
            {
                "_smtp._tls.example.com": [
                    '"v=TLSRPTv1; rua=mailto:reports@example.com,'
                    'https://r.example.com/x"'
                ]
            }
        )
        self._scan(resolver)
        self.assertTrue(self.domain.has_tlsrpt_record)
        self.assertTrue(self.domain.valid_tlsrpt)
        self.assertEqual(
            self.domain.tlsrpt_ruas,
            ["mailto:reports@example.com", "https://r.example.com/x"],
        )

    def test_missing_rua_is_invalid(self):
        """A record without a rua tag is invalid."""
        resolver = _FakeResolver({"_smtp._tls.example.com": ['"v=TLSRPTv1;"']})
        self._scan(resolver)
        self.assertTrue(self.domain.has_tlsrpt_record)
        self.assertFalse(self.domain.valid_tlsrpt)

    def test_invalid_rua_uri_is_invalid(self):
        """A rua URI with an unsupported scheme is invalid."""
        resolver = _FakeResolver(
            {"_smtp._tls.example.com": ['"v=TLSRPTv1; rua=ftp://example.com"']}
        )
        self._scan(resolver)
        self.assertFalse(self.domain.valid_tlsrpt)

    def test_absent_record(self):
        """A domain with no record reports has_tlsrpt_record False."""
        self._scan(_FakeResolver({}))
        self.assertFalse(self.domain.has_tlsrpt_record)
        self.assertFalse(self.domain.valid_tlsrpt)


class TestGenerateResults(unittest.TestCase):
    """Test that the results dictionary exposes the expected fields."""

    def test_mta_sts_and_tlsrpt_columns_present(self):
        """The MTA-STS and TLS-RPT fields appear in the results."""
        domain = _make_domain()
        domain.has_mta_sts_record = True
        domain.valid_mta_sts = True
        domain.mta_sts_record = "v=STSv1; id=123"
        domain.mta_sts_policy_mode = "enforce"
        domain.mta_sts_policy_mx = ["mail.example.com"]
        domain.mta_sts_policy_max_age = 86400
        domain.has_tlsrpt_record = True
        domain.valid_tlsrpt = True
        domain.tlsrpt_record = "v=TLSRPTv1; rua=mailto:r@example.com"
        domain.tlsrpt_ruas = ["mailto:r@example.com"]

        results = domain.generate_results()
        for key in (
            "MTA-STS Record",
            "MTA-STS Record DNSSEC",
            "Valid MTA-STS",
            "MTA-STS Results",
            "MTA-STS Policy Mode",
            "MTA-STS Policy MX",
            "MTA-STS Policy Max Age",
            "TLS-RPT Record",
            "TLS-RPT Record DNSSEC",
            "Valid TLS-RPT",
            "TLS-RPT Results",
            "TLS-RPT Report URIs",
        ):
            self.assertIn(key, results)

        self.assertEqual(results["MTA-STS Policy Mode"], "enforce")
        # Lists are rendered as comma-separated strings.
        self.assertEqual(results["MTA-STS Policy MX"], "mail.example.com")
        self.assertEqual(results["TLS-RPT Report URIs"], "mailto:r@example.com")

    def test_new_columns_default_to_none_when_not_scanned(self):
        """Unscanned MTA-STS/TLS-RPT presence flags default to None."""
        domain = _make_domain()
        results = domain.generate_results()
        self.assertIsNone(results["MTA-STS Record"])
        self.assertIsNone(results["TLS-RPT Record"])


if __name__ == "__main__":
    pytest.main([__file__])
