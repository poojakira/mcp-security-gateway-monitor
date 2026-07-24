"""Tests for PIIDetector — 25 tests."""

import pytest
from mcp_monitor.detectors.pii_detector import PII_PATTERNS, PIIDetector


@pytest.fixture
def detector():
    return PIIDetector()


# --- Detection tests ---


class TestDetection:
    def test_detect_email(self, detector):
        result = detector.detect("Contact me at alice@example.com please")
        assert "email" in result
        assert "alice@example.com" in result["email"]

    def test_detect_multiple_emails(self, detector):
        text = "Send to bob@test.org and carol@work.co.uk"
        result = detector.detect(text)
        assert "email" in result
        assert len(result["email"]) == 2

    def test_detect_ssn(self, detector):
        result = detector.detect("SSN: 123-45-6789")
        assert "ssn" in result
        assert "123-45-6789" in result["ssn"]

    def test_detect_credit_card_spaces(self, detector):
        result = detector.detect("Card: 4111 1111 1111 1111")
        assert "credit_card" in result

    def test_detect_credit_card_dashes(self, detector):
        result = detector.detect("Card: 4111-1111-1111-1111")
        assert "credit_card" in result

    def test_detect_credit_card_continuous(self, detector):
        result = detector.detect("Card: 4111111111111111")
        assert "credit_card" in result

    def test_detect_phone_us(self, detector):
        result = detector.detect("Call 555-867-5309")
        assert "phone_us" in result

    def test_detect_phone_dots(self, detector):
        result = detector.detect("Phone: 555.867.5309")
        assert "phone_us" in result

    def test_detect_ip_address(self, detector):
        result = detector.detect("Server at 192.168.1.1")
        assert "ip_address" in result
        assert "192.168.1.1" in result["ip_address"]

    def test_detect_date_of_birth(self, detector):
        result = detector.detect("DOB: 01/15/1990")
        assert "date_of_birth" in result

    def test_detect_passport(self, detector):
        result = detector.detect("Passport: AB1234567")
        assert "passport" in result

    def test_detect_aws_key(self, detector):
        result = detector.detect("Key: AKIAIOSFODNN7EXAMPLE")
        assert "aws_key" in result

    def test_detect_api_key(self, detector):
        result = detector.detect("Token: sk-live-abcdefghijklmnopqrstuvwx")
        assert "api_key" in result

    def test_no_pii_clean_text(self, detector):
        result = detector.detect("Hello world, nothing sensitive here.")
        assert result == {}

    def test_minimum_8_pii_types(self, detector):
        assert len(PII_PATTERNS) >= 8


# --- Redaction tests ---


class TestRedaction:
    def test_pii_redaction_credit_card(self, detector):
        text = "Pay with 4111 1111 1111 1111 please"
        redacted = detector.redact(text)
        assert "4111" not in redacted
        assert "[REDACTED]" in redacted

    def test_redact_email(self, detector):
        text = "Email: secret@corp.com"
        redacted = detector.redact(text)
        assert "secret@corp.com" not in redacted
        assert "[REDACTED]" in redacted

    def test_redact_ssn(self, detector):
        text = "SSN is 999-88-7777"
        redacted = detector.redact(text)
        assert "999-88-7777" not in redacted

    def test_redact_custom_replacement(self, detector):
        text = "IP: 10.0.0.1"
        redacted = detector.redact(text, replacement="***")
        assert "10.0.0.1" not in redacted
        assert "***" in redacted

    def test_redact_multiple_types(self, detector):
        text = "alice@test.com SSN 123-45-6789 card 4111111111111111"
        redacted = detector.redact(text)
        assert "alice@test.com" not in redacted
        assert "123-45-6789" not in redacted
        assert "4111111111111111" not in redacted


# --- Tool-call scanning tests ---


class TestScanToolCall:
    def test_scan_tool_call_with_pii(self, detector):
        call = {
            "name": "email.send",
            "arguments": {"to": "user@corp.com", "body": "SSN: 111-22-3333"},
        }
        has_pii, findings = detector.scan_tool_call(call)
        assert has_pii
        assert "email" in findings
        assert "ssn" in findings

    def test_scan_tool_call_clean(self, detector):
        call = {"name": "math.add", "arguments": {"a": "5", "b": "10"}}
        has_pii, findings = detector.scan_tool_call(call)
        assert not has_pii
        assert findings == {}

    def test_scan_tool_call_nested(self, detector):
        call = {
            "name": "db.query",
            "arguments": {
                "filter": {"user_email": "test@example.com"},
                "fields": ["name", "phone"],
            },
        }
        has_pii, findings = detector.scan_tool_call(call)
        assert has_pii
        assert "email" in findings

    def test_scan_tool_call_list_values(self, detector):
        call = {
            "name": "bulk",
            "arguments": {"emails": ["a@b.com", "c@d.org"]},
        }
        has_pii, findings = detector.scan_tool_call(call)
        assert has_pii
        assert len(findings["email"]) == 2

    def test_scan_tool_call_ip_in_config(self, detector):
        call = {
            "name": "deploy",
            "arguments": {"host": "10.0.0.55", "port": "8080"},
        }
        has_pii, findings = detector.scan_tool_call(call)
        assert has_pii
        assert "ip_address" in findings
