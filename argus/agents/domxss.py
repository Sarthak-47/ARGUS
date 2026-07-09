"""DomXSSHunter — DOM-based XSS via a real headless browser (opt-in).

XSSHunter is HTTP+regex only: it can only see markup the *server* renders, so
it's blind to DOM XSS in client-rendered apps (React/Vue/Next) where untrusted
input flows into innerHTML, document.write, or a similar sink entirely inside
the browser. This agent launches headless Chromium via Playwright, navigates
each discovered URL with an injected payload, and checks for actual script
execution — proof via a real browser, not a pattern guess.

Optional dependency (``pip install argus-panoptes[browser]`` then
``playwright install chromium``). Degrades gracefully and stays out of the
default agent order when unavailable — same pattern semgrep_runner.py uses for
Semgrep — so it never affects a standard install or a default attack run.
"""

from __future__ import annotations

from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from argus.agents.base import AgentReport, AttackContext, BaseAgent
from argus.models import Finding, Severity

try:
    from playwright.async_api import async_playwright
except ImportError:  # pragma: no cover - exercised only when the extra isn't installed
    async_playwright = None

_SENTINEL_PAYLOAD = '"><img src=x onerror="window.__argus_dom_xss=true">'
_CHECK_JS = "window.__argus_dom_xss === true"
_GUESS_PARAMS = ["q", "search", "name", "query", "s"]


def _with_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    qs[param] = [value]
    new_q = urlencode({k: v[0] for k, v in qs.items()})
    return urlunparse(parsed._replace(query=new_q))


class DomXSSHunter(BaseAgent):
    name = "DomXSSHunter"
    description = "DOM XSS via headless browser (opt-in)"

    async def run(self, ctx: AttackContext) -> AgentReport:
        report = AgentReport(agent=self.name, status="running")

        if async_playwright is None:
            ctx.emit(self.name, "playwright not installed — skipping "
                                 "(pip install 'argus-panoptes[browser]' && playwright install chromium)")
            report.status = "complete"
            return report

        targets = self._targets(ctx)
        if not targets:
            ctx.emit(self.name, "no GET parameters to test")
            report.status = "complete"
            return report

        confirmed = 0
        async with async_playwright() as pw:
            browser = await pw.chromium.launch()
            try:
                page = await browser.new_page()
                for ep_url, param in targets:
                    test_url = _with_param(ep_url, param, _SENTINEL_PAYLOAD)
                    ctx.emit(self.name, f"testing {param} on {self._short(ep_url)} in a real browser …")
                    try:
                        await page.goto(test_url, timeout=8000, wait_until="load")
                        await page.wait_for_timeout(200)
                        fired = await page.evaluate(_CHECK_JS)
                    except Exception:
                        continue
                    ctx.requests_sent += 1
                    if fired:
                        confirmed += 1
                        ctx.report(Finding(
                            title="DOM-based XSS",
                            severity=Severity.HIGH,
                            category="xss",
                            detector="domxss:confirmed",
                            endpoint=f"GET {ep_url}",
                            evidence=f"param '{param}' payload executed in a real browser "
                                     f"({_CHECK_JS} was true after navigation)",
                            description="Input reaches a client-side DOM sink (innerHTML/"
                                        "document.write or similar) and executes as script — "
                                        "confirmed via actual browser execution, not a pattern guess.",
                            exploit="Deliver a crafted link; the script runs in the victim's "
                                    "browser session with no server-side involvement at all.",
                            fix="Never assign untrusted data to innerHTML/outerHTML/document.write; "
                                "use textContent, or sanitise with a vetted library (e.g. DOMPurify) "
                                "before inserting HTML.",
                            cwe="CWE-79",
                            cvss=6.1,
                            confidence="high",
                            poc={"type": "browser", "url": test_url,
                                 "notes": f"Navigate to this URL in a real browser; {_CHECK_JS} "
                                          f"becomes true, proving the payload executed."},
                        ))
            finally:
                await browser.close()

        report.requests_sent = ctx.requests_sent
        report.findings = len([f for f in ctx.findings if f.detector == "domxss:confirmed"])
        report.status = "complete"
        ctx.emit(self.name, f"sweep complete — {confirmed} confirmed", "ok")
        return report

    def _targets(self, ctx: AttackContext) -> list[tuple[str, str]]:
        out: list[tuple[str, str]] = []
        for ep in ctx.endpoint_list():
            if ep.method != "GET":
                continue
            for p in (ep.params or _GUESS_PARAMS[:3]):
                out.append((ep.url, p))
        return out[:20]

    @staticmethod
    def _short(url: str) -> str:
        p = urlparse(url)
        return (p.path or "/") + ("?" + p.query if p.query else "")
