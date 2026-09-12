#!/usr/bin/env python3
"""Regenerate every public surface that repeats the release version or the
changelog, from the two files that actually own that information:
``pyproject.toml`` (the current version) and ``CHANGELOG.md`` (the history).

These surfaces have drifted twice running: the marketing site's changelog page
sat eighteen releases behind before one hand-catch-up, then fell behind again
on the very next tag, and the README kept advertising a stale ``pre-commit``
rev. Hand-syncing five files on every release is a chore that will keep being
forgotten, so derive them instead — and ``--check`` (wired into CI) fails the
build when they no longer match, rather than letting a stale version reach a
visitor.

Usage:
    python scripts/sync_release_docs.py           # rewrite the files
    python scripts/sync_release_docs.py --check   # exit 1 if out of sync
"""

from __future__ import annotations

import argparse
import html
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

CHANGELOG = REPO / "CHANGELOG.md"
PYPROJECT = REPO / "pyproject.toml"
README = REPO / "README.md"
SITE_CHANGELOG = REPO / "website" / "changelog" / "index.html"
SITE_FEED = REPO / "website" / "changelog" / "feed.xml"
SITE_DOWNLOAD = REPO / "website" / "download" / "index.html"

# How many releases the site renders inline. The rest stay one click away in
# CHANGELOG.md on GitHub, which the page already links to — rendering all forty
# would bury the recent ones a reader actually came for.
SITE_RELEASES = 20

RELEASE_URL = "https://github.com/Sarthak-47/ARGUS/releases/tag/v{version}"


@dataclass
class Section:
    """One ``### Added`` / ``### Fixed`` block within a release."""

    name: str
    lead: list[str] = field(default_factory=list)  # prose before the bullets
    bullets: list[str] = field(default_factory=list)


@dataclass
class Release:
    version: str
    date: str  # ISO, as written in CHANGELOG.md
    sections: list[Section] = field(default_factory=list)

    @property
    def summary(self) -> str:
        """Plain-text one-liner for the RSS description: the release's first
        bullet, which by convention is its headline change."""
        for section in self.sections:
            if section.bullets:
                return md_to_text(section.bullets[0])
            if section.lead:
                return md_to_text(" ".join(section.lead))
        return f"Argus {self.version}."


# --------------------------------------------------------------------------- #
# parsing
# --------------------------------------------------------------------------- #

RELEASE_RE = re.compile(r"^## \[(?P<version>\d+\.\d+\.\d+)\]\s+—\s+(?P<date>\d{4}-\d{2}-\d{2})\s*$")
SECTION_RE = re.compile(r"^### (?P<name>.+?)\s*$")


def parse_changelog(text: str) -> list[Release]:
    """Parse CHANGELOG.md into releases. ``## [Unreleased]`` is skipped — it has
    no version or date to publish, and shipping it to the site would advertise
    work that isn't in anyone's installer yet."""
    releases: list[Release] = []
    release: Release | None = None
    section: Section | None = None
    # CHANGELOG.md hard-wraps prose, so a paragraph is several source lines and
    # only a blank line actually ends it. Without tracking that, one wrapped
    # sentence renders as one <p> per source line.
    after_blank = True

    for raw in text.splitlines():
        line = raw.rstrip()

        if not line.strip():
            after_blank = True
            continue

        if line.startswith("## "):
            match = RELEASE_RE.match(line)
            release = Release(match["version"], match["date"]) if match else None
            if release is not None:
                releases.append(release)
            section = None
            after_blank = True
            continue

        if release is None:
            after_blank = False
            continue

        heading = SECTION_RE.match(line)
        if heading:
            section = Section(heading["name"])
            release.sections.append(section)
            after_blank = True
            continue

        if section is None:
            # Prose sitting directly under the release header with no ###
            # section of its own (0.1.0's "Initial tagged release.").
            section = Section("")
            release.sections.append(section)

        if line.startswith("- "):
            section.bullets.append(line[2:].strip())
        elif line.startswith("  ") and section.bullets and not after_blank:
            # Continuation of the previous bullet.
            section.bullets[-1] += " " + line.strip()
        elif section.lead and not after_blank:
            section.lead[-1] += " " + line.strip()
        else:
            section.lead.append(line.strip())

        after_blank = False

    return releases


# --------------------------------------------------------------------------- #
# markdown → html / text
# --------------------------------------------------------------------------- #

LINK_RE = re.compile(r"\[([^\]]+)\]\((https?://[^)\s]+)\)")
# Non-greedy and *-tolerant so a bold span can wrap a nested italic
# (``**a *b* c**``); ``[^*]+`` broke on the inner asterisks and produced
# mangled <em> nesting. Bold is converted before italic, leaving the inner
# ``*b*`` for ITALIC_RE to pick up inside the <b>.
BOLD_RE = re.compile(r"\*\*(.+?)\*\*")
# Runs only after BOLD_RE, so a ``**bold**`` run is already consumed and can't
# be mistaken for a pair of single-asterisk emphases.
ITALIC_RE = re.compile(r"\*([^*\n]+)\*")
CODE_RE = re.compile(r"`([^`]+)`")


def md_to_html(text: str) -> str:
    escaped = html.escape(text, quote=False)
    escaped = LINK_RE.sub(r'<a href="\2" target="_blank" rel="noopener">\1</a>', escaped)
    escaped = BOLD_RE.sub(r"<b>\1</b>", escaped)
    escaped = ITALIC_RE.sub(r"<em>\1</em>", escaped)
    return CODE_RE.sub(r"<code>\1</code>", escaped)


def md_to_text(text: str) -> str:
    plain = LINK_RE.sub(r"\1", text)
    plain = BOLD_RE.sub(r"\1", plain)
    plain = ITALIC_RE.sub(r"\1", plain)
    plain = CODE_RE.sub(r"\1", plain)
    return html.escape(plain, quote=False)


# --------------------------------------------------------------------------- #
# rendering
# --------------------------------------------------------------------------- #

def render_site_entries(releases: list[Release]) -> str:
    out: list[str] = []
    for release in releases[:SITE_RELEASES]:
        out.append('    <div class="rel-entry">')
        out.append(f"      <h3>{release.version}</h3>")
        out.append(f'      <span class="date">{release.date}</span>')
        for section in release.sections:
            if section.name:
                out.append(f"      <h4>{section.name}</h4>")
            for lead in section.lead:
                out.append(f"      <p>{md_to_html(lead)}</p>")
            if section.bullets:
                out.append("      <ul>")
                for bullet in section.bullets:
                    out.append(f"        <li>{md_to_html(bullet)}</li>")
                out.append("      </ul>")
        out.append("    </div>")
        out.append("")
    return "\n".join(out)


def rfc822(date: str) -> str:
    parsed = datetime.strptime(date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    return parsed.strftime("%a, %d %b %Y 00:00:00 GMT")


def render_feed_items(releases: list[Release]) -> str:
    out: list[str] = []
    for release in releases[:SITE_RELEASES]:
        url = RELEASE_URL.format(version=release.version)
        out.append("    <item>")
        out.append(f"      <title>{release.version}</title>")
        out.append(f"      <link>{url}</link>")
        out.append(f"      <guid>{url}</guid>")
        out.append(f"      <pubDate>{rfc822(release.date)}</pubDate>")
        out.append(f"      <description>{release.summary}</description>")
        out.append("    </item>")
    return "\n".join(out)


# --------------------------------------------------------------------------- #
# file rewriting
# --------------------------------------------------------------------------- #

def replace_between(text: str, start: str, end: str, body: str, path: Path) -> str:
    """Swap the region between two marker comments, keeping the markers.

    The replacement is written out in full rather than reusing the matched
    whitespace, so running this twice produces the same bytes — otherwise
    ``--check`` reports drift against output this script itself just wrote.
    (A function repl also stops ``re.sub`` from interpreting backslashes in
    the generated body as group references.)"""
    pattern = re.compile(
        rf"{re.escape(start)}\n.*?\n[ \t]*{re.escape(end)}", re.DOTALL
    )
    if not pattern.search(text):
        raise SystemExit(
            f"{path}: missing the '{start}' / '{end}' markers this script "
            f"regenerates between — restore them, or update this script."
        )
    replacement = f"{start}\n{body.rstrip()}\n{end}"
    return pattern.sub(lambda _: replacement, text)


def current_version() -> str:
    match = re.search(r'^version = "(\d+\.\d+\.\d+)"', PYPROJECT.read_text(encoding="utf-8"), re.M)
    if not match:
        raise SystemExit(f"{PYPROJECT}: could not find a version.")
    return match[1]


def build_updates(version: str, releases: list[Release]) -> dict[Path, str]:
    """Return {path: desired content} for every derived file."""
    updates: dict[Path, str] = {}

    readme = README.read_text(encoding="utf-8")
    readme = re.sub(r"(rev: v)\d+\.\d+\.\d+", rf"\g<1>{version}", readme)
    readme = re.sub(r"(v0\.1\.0–v)\d+\.\d+\.\d+( published)", rf"\g<1>{version}\g<2>", readme)
    updates[README] = readme

    download = SITE_DOWNLOAD.read_text(encoding="utf-8")
    download = re.sub(
        r'(<div class="eyebrow">v)\d+\.\d+\.\d+', rf"\g<1>{version}", download
    )
    updates[SITE_DOWNLOAD] = download

    page = SITE_CHANGELOG.read_text(encoding="utf-8")
    updates[SITE_CHANGELOG] = replace_between(
        page, "<!-- releases:start -->", "<!-- releases:end -->",
        render_site_entries(releases), SITE_CHANGELOG,
    )

    feed = SITE_FEED.read_text(encoding="utf-8")
    updates[SITE_FEED] = replace_between(
        feed, "<!-- items:start -->", "<!-- items:end -->",
        render_feed_items(releases), SITE_FEED,
    )

    return updates


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check", action="store_true",
        help="Don't write anything; exit 1 if any derived file is out of date.",
    )
    args = parser.parse_args()

    version = current_version()
    releases = parse_changelog(CHANGELOG.read_text(encoding="utf-8"))
    if not releases:
        raise SystemExit(f"{CHANGELOG}: no releases parsed — has the format changed?")

    if releases[0].version != version:
        raise SystemExit(
            f"pyproject.toml is at {version} but CHANGELOG.md's newest release is "
            f"{releases[0].version}. Add the release section before syncing."
        )

    updates = build_updates(version, releases)
    stale = [path for path, desired in updates.items() if path.read_text(encoding="utf-8") != desired]

    if args.check:
        if stale:
            print("Release docs are out of sync with CHANGELOG.md / pyproject.toml:")
            for path in stale:
                print(f"  - {path.relative_to(REPO).as_posix()}")
            print("\nRun: python scripts/sync_release_docs.py")
            return 1
        print(f"Release docs are in sync (v{version}).")
        return 0

    for path in stale:
        # Explicit LF: .gitattributes pins the repo to eol=lf, and a generated
        # file should be byte-identical whoever regenerates it. Without this,
        # text-mode writes emit CRLF on Windows and LF elsewhere, so the same
        # command produces a different file depending on the machine.
        path.write_text(updates[path], encoding="utf-8", newline="\n")
        print(f"updated {path.relative_to(REPO).as_posix()}")
    if not stale:
        print(f"Already in sync (v{version}).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
