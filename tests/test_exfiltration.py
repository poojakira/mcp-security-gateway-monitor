"""Tests for ExfiltrationDetector — 20 tests."""

import base64

import pytest

from mcp_monitor.detectors.exfiltration import ExfiltrationDetector


@pytest.fixture
def detector():
    return ExfiltrationDetector(max_payload_kb=10.0)


# --- BCC Injection tests (the real Postmark attack) ---


class TestBCCInjection:
    def test_bcc_injection_detection(self, detector):
        """Core test: detect the real-world BCC exfiltration attack."""
        payload = {
            "to": ["user@company.com"],
            "subject": "Invoice",
            "body": "Please find attached.",
            "bcc": ["attacker@evil.com"],
        }
        assert detector.detect_bcc_injection(payload) is True

    def test_bcc_injection_string_field(self, detector):
        payload = {"to": "user@x.com", "bcc": "attacker@giftshop.club"}
        assert detector.detect_bcc_injection(payload) is True

    def test_bcc_injection_in_headers(self, detector):
        payload = {
            "to": ["user@x.com"],
            "headers": {"Bcc": "hidden@evil.com"},
        }
        assert detector.detect_bcc_injection(payload) is True

    def test_bcc_injection_nested_message(self, detector):
        payload = {
            "message": {"to": "user@x.com", "bcc": ["stealth@bad.com"]},
        }
        assert detector.detect_bcc_injection(payload) is True

    def test_no_bcc_clean_email(self, detector):
        payload = {"to": ["user@x.com"], "subject": "Hi", "body": "Hello"}
        assert detector.detect_bcc_injection(payload) is False

    def test_empty_bcc_list_safe(self, detector):
        payload = {"to": ["user@x.com"], "bcc": []}
        assert detector.detect_bcc_injection(payload) is False

    def test_empty_bcc_string_safe(self, detector):
        payload = {"to": ["user@x.com"], "bcc": ""}
        assert detector.detect_bcc_injection(payload) is False

    def test_x_bcc_header_detected(self, detector):
        payload = {"to": "x@y.com", "headers": {"x-bcc": "hidden@z.com"}}
        assert detector.detect_bcc_injection(payload) is True


# --- Full detect() method tests ---


class TestDetect:
    def test_email_tool_bcc_detected(self, detector):
        output = {"to": ["user@x.com"], "bcc": ["attacker@evil.com"]}
        detected, reasons = detector.detect("email.send", output)
        assert detected
        assert any("BCC" in r for r in reasons)

    def test_non_email_tool_bcc_ignored(self, detector):
        output = {"to": ["user@x.com"], "bcc": ["someone@x.com"]}
        detected, reasons = detector.detect("math.add", output)
        # Not an email tool so BCC check is skipped
        assert not any("BCC" in r for r in reasons)

    def test_large_payload_flagged(self, detector):
        output = {"data": "x" * 20_000}  # ~20KB > 10KB limit
        detected, reasons = detector.detect("any.tool", output)
        assert detected
        assert any("payload size" in r for r in reasons)

    def test_small_payload_safe(self, detector):
        output = {"data": "small"}
        detected, reasons = detector.detect("any.tool", output)
        assert not detected

    def test_base64_large_blob_flagged(self, detector):
        # Create a base64 blob > 1KB decoded
        raw_data = b"A" * 2000
        b64 = base64.b64encode(raw_data).decode("ascii")
        output = {"payload": b64}
        detected, reasons = detector.detect("file.upload", output)
        assert detected
        assert any("base64" in r for r in reasons)

    def test_base64_small_blob_safe(self, detector):
        raw_data = b"hello"
        b64 = base64.b64encode(raw_data).decode("ascii")
        output = {"payload": b64}
        detected, reasons = detector.detect("file.upload", output)
        # Small blob, no flag
        assert not any("base64" in r for r in reasons)

    def test_suspicious_url_raw_ip(self, detector):
        output = {"redirect": "http://123.45.67.89/steal"}
        detected, reasons = detector.detect("web.fetch", output)
        assert detected
        assert any("suspicious URL" in r for r in reasons)

    def test_suspicious_url_ngrok(self, detector):
        output = {"url": "https://abc123.ngrok.io/exfil"}
        detected, reasons = detector.detect("web.call", output)
        assert detected

    def test_suspicious_url_webhook_site(self, detector):
        output = {"callback": "https://webhook.site/abc-123"}
        detected, reasons = detector.detect("hook.register", output)
        assert detected

    def test_clean_url_not_flagged(self, detector):
        output = {"url": "https://api.github.com/repos"}
        detected, reasons = detector.detect("github.api", output)
        # No suspicious patterns
        assert not any("suspicious URL" in r for r in reasons)

    def test_postmark_tool_name_recognized(self, detector):
        output = {"to": "x@y.com", "bcc": ["evil@bad.com"]}
        detected, reasons = detector.detect("postmark.send_email", output)
        assert detected
        assert any("BCC" in r for r in reasons)

    def test_sendgrid_tool_name_recognized(self, detector):
        output = {"to": "x@y.com", "bcc": ["evil@bad.com"]}
        detected, reasons = detector.detect("sendgrid.mail", output)
        assert detected
