"""Alerting hooks for critical security findings.

Posts JSON webhooks to configurable URLs (Slack/PagerDuty compatible)
when findings exceed a risk threshold. Uses fire-and-forget threading.
"""

from __future__ import annotations

import json
import threading
import time
import urllib.request
import urllib.error
from typing import Any, Optional

from mcp_monitor.production.logging import get_logger

_logger = get_logger(__name__)


class AlertingHook:
    """Webhook alerting for critical findings.

    Parameters
    ----------
    webhook_url:
        URL to POST alerts to (Slack incoming webhook or PagerDuty).
    risk_threshold:
        Minimum risk_score to trigger an alert. Default 80.
    cooldown_seconds:
        Minimum time between alerts for the same finding type. Default 60.
    """

    def __init__(
        self,
        webhook_url: Optional[str] = None,
        risk_threshold: int = 80,
        cooldown_seconds: float = 60.0,
    ) -> None:
        self.webhook_url = webhook_url
        self.risk_threshold = risk_threshold
        self.cooldown_seconds = cooldown_seconds
        self._last_alert_times: dict[str, float] = {}
        self._lock = threading.Lock()

    def check_and_alert(self, result: dict[str, Any]) -> bool:
        """Check a monitor result and fire alert if needed.

        Parameters
        ----------
        result:
            Dict from inspect_call/inspect_output with risk_score and findings.

        Returns
        -------
        True if an alert was fired, False otherwise.
        """
        if not self.webhook_url:
            return False

        risk_score = result.get("risk_score", 0)
        if risk_score < self.risk_threshold:
            return False

        # Cooldown check
        findings_key = ",".join(sorted(result.get("findings", [])))
        now = time.time()
        with self._lock:
            last_time = self._last_alert_times.get(findings_key, 0.0)
            if now - last_time < self.cooldown_seconds:
                return False
            self._last_alert_times[findings_key] = now

        # Fire alert in background thread
        alert_payload = self._build_payload(result)
        thread = threading.Thread(
            target=self._send_webhook,
            args=(alert_payload,),
            daemon=True,
        )
        thread.start()
        return True

    def _build_payload(self, result: dict[str, Any]) -> dict[str, Any]:
        """Build a Slack/PagerDuty compatible webhook payload."""
        findings = result.get("findings", [])
        risk_score = result.get("risk_score", 0)
        call_id = result.get("call_id", "unknown")

        return {
            "text": (
                f"[CRITICAL] MCP Security Alert - Risk Score: {risk_score}"
            ),
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            f"*MCP Security Alert*\n"
                            f"Risk Score: {risk_score}/100\n"
                            f"Call ID: {call_id}\n"
                            f"Findings: {', '.join(findings)}"
                        ),
                    },
                }
            ],
            "severity": "critical",
            "source": "mcp-security-monitor",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "call_id": call_id,
            "risk_score": risk_score,
            "findings": findings,
        }

    def _send_webhook(self, payload: dict[str, Any]) -> None:
        """Send webhook POST (fire-and-forget)."""
        if not self.webhook_url:
            return
        try:
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                self.webhook_url,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            urllib.request.urlopen(req, timeout=10)
        except Exception as exc:
            # Fire-and-forget: log error but don't raise
            _logger.warning(
                f"Webhook alert failed: {exc}",
                extra={"extra_fields": {"webhook_url": self.webhook_url}},
            )
