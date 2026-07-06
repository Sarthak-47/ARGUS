"""Best-effort Slack/Discord webhook notifications on scan completion.

Scoped down from a full ticketing integration (Jira/Linear, what Aikido
offers) to a single webhook POST — a solo dev or small team already lives in
Slack/Discord, and standing up a ticketing workflow for a one-person team is
overkill. One URL, no OAuth, no per-provider SDK.

Slack's incoming-webhook format wants a top-level "text" key; Discord's wants
"content". Both platforms silently ignore unknown top-level keys, so sending
both in the same payload works for either without needing to sniff the URL.
"""

from __future__ import annotations

import httpx

from argus.models import ScanResult


def _message_for(result: ScanResult) -> str:
    counts = result.counts()
    crit = counts.get("CRITICAL", 0)
    high = counts.get("HIGH", 0)
    return (
        f"*Argus scan complete* — `{result.target}`\n"
        f"Risk score: *{result.risk_score}/100* ({result.risk_band}) · "
        f"{crit} critical · {high} high · {len(result.findings)} total finding(s)"
    )


def notify_scan_complete(webhook_url: str, result: ScanResult) -> bool:
    """POST a scan summary to a configured webhook. Returns True on success.

    Never raises — a notification failing must never break the scan it's
    reporting on. Returns False (rather than raising) so the caller can
    decide whether/how loudly to warn the user.
    """
    if not webhook_url:
        return False
    message = _message_for(result)
    try:
        resp = httpx.post(webhook_url, json={"text": message, "content": message}, timeout=8.0)
        return resp.status_code < 400
    except httpx.HTTPError:
        return False
