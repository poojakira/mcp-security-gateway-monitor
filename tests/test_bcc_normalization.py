"""Regression tests for BCC/header normalization bypasses."""

import pytest

from mcp_monitor.detectors.exfiltration import ExfiltrationDetector


@pytest.mark.parametrize(
    "payload",
    [
        {"carbon_copy": "hidden@example.com"},
        {"rcpt_to": ["hidden@example.com"]},
        {"raw": "To: user@example.com\nBcc: hidden@example.com\nSubject: x\n\nbody"},
        {"headers": {"b\u0441\u0441": "hidden@example.com"}},
        {
            "raw": (
                "MIME-Version: 1.0\n"
                "Content-Type: multipart/mixed; boundary=x\n\n"
                "--x\n"
                "Content-Type: text/plain\n"
                "Bcc: hidden@example.com\n\n"
                "body\n"
                "--x--\n"
            )
        },
    ],
)
def test_bcc_normalization_detects_missed_cases(payload):
    detector = ExfiltrationDetector()
    assert detector.detect_bcc_injection(payload) is True