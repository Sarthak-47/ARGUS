"""Core data models shared across every Argus phase and module.

These are deliberately plain dataclasses (no pydantic dependency at runtime) so the
engine stays light and every module — scanner, agents, report — speaks the same
vocabulary: a finding has a severity, a location, an explanation, and a fix.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Vulnerability severity. Order matters: used for sorting and risk scoring."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        """Higher = more severe. Used to sort findings worst-first."""
        return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}[self.value]

    @property
    def weight(self) -> int:
        """Contribution to the 0-100 risk score."""
        return {"CRITICAL": 40, "HIGH": 20, "MEDIUM": 8, "LOW": 3, "INFO": 0}[self.value]

    @property
    def color(self) -> str:
        """Hex colour from the 'carved in stone' design system."""
        return {
            "CRITICAL": "#8B0000",  # deep crimson
            "HIGH": "#8B4513",      # burnt sienna
            "MEDIUM": "#B8860B",    # dark goldenrod
            "LOW": "#4A4035",       # weathered stone
            "INFO": "#2A2A3A",      # almost invisible
        }[self.value]

    @property
    def rich_style(self) -> str:
        """Closest Rich/ANSI style for terminal output (no green/blue/purple)."""
        return {
            "CRITICAL": "bold red",
            "HIGH": "dark_orange3",
            "MEDIUM": "yellow3",
            "LOW": "grey58",
            "INFO": "grey37",
        }[self.value]

    @classmethod
    def coerce(cls, value: str | "Severity") -> "Severity":
        if isinstance(value, cls):
            return value
        try:
            return cls(str(value).strip().upper())
        except ValueError:
            return cls.INFO


@dataclass
class Finding:
    """A single security finding from any phase or detector."""

    title: str
    severity: Severity
    category: str = "misc"          # e.g. "injection", "secret", "dependency", "auth"
    detector: str = "argus"         # which module/agent produced it
    description: str = ""           # plain-English explanation (LLM-enriched when available)
    file: str | None = None         # relative path within the repo
    line: int | None = None
    endpoint: str | None = None     # for Phase 2 / HTTP findings
    evidence: str = ""              # matched snippet / HTTP request-response
    exploit: str = ""               # exploit scenario
    fix: str = ""                   # concrete remediation, ideally a diff
    poc: dict[str, Any] = field(default_factory=dict)  # reproducible proof: {"type","curl","request","response"}
    cvss: float | None = None
    cwe: str | None = None
    confidence: str = "medium"      # low | medium | high
    references: list[str] = field(default_factory=list)
    confirmed: bool = False         # True when an attack agent actually exploited it
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    created_at: float = field(default_factory=time.time)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.severity = Severity.coerce(self.severity)

    @property
    def location(self) -> str:
        if self.endpoint:
            return self.endpoint
        if self.file and self.line:
            return f"{self.file}:{self.line}"
        return self.file or "—"

    def dedup_key(self) -> tuple:
        """Identity used to merge near-duplicate findings from different detectors.

        Keyed on category + location + line + normalized title (not on ``id``, which
        is random per-instance). Two findings collide only when they plausibly describe
        the same underlying issue at the same spot — safer than keying on detector alone,
        which would wrongly merge distinct bugs that happen to share a line.
        """
        loc = (self.file or self.endpoint or "").lower()
        return (self.category, loc, self.line, self.title.strip().lower())

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class CodebaseMap:
    """The structural understanding of a repo built during ingestion."""

    root: str
    languages: dict[str, int] = field(default_factory=dict)   # language -> file count
    frameworks: list[str] = field(default_factory=list)
    entry_points: list[str] = field(default_factory=list)
    auth_files: list[str] = field(default_factory=list)
    db_files: list[str] = field(default_factory=list)
    config_files: list[str] = field(default_factory=list)
    dependency_manifests: list[str] = field(default_factory=list)
    external_calls: list[str] = field(default_factory=list)
    high_risk_files: list[str] = field(default_factory=list)
    file_count: int = 0
    total_loc: int = 0

    @property
    def primary_language(self) -> str | None:
        if not self.languages:
            return None
        return max(self.languages, key=self.languages.get)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["primary_language"] = self.primary_language
        return d


_CONFIDENCE_RANK = {"low": 0, "medium": 1, "high": 2}


@dataclass
class ScanResult:
    """The complete result of a scan/attack/audit — what the report is built from."""

    target: str
    phase: str = "scan"             # scan | attack | audit
    codebase_map: CodebaseMap | None = None
    findings: list[Finding] = field(default_factory=list)
    started_at: float = field(default_factory=time.time)
    finished_at: float | None = None
    llm_provider: str | None = None
    errors: list[str] = field(default_factory=list)
    _seen: dict[tuple, Finding] = field(default_factory=dict, init=False, repr=False, compare=False)

    # ----- aggregation helpers -----
    def add(self, finding: Finding) -> None:
        """Append a finding, merging it into an existing near-duplicate if one exists.

        Detectors regularly overlap (a built-in rule and Semgrep flagging the same SQLi
        line, for instance); without this, the same bug shows up twice in every report.
        """
        key = finding.dedup_key()
        existing = self._seen.get(key)
        if existing is None:
            self._seen[key] = finding
            self.findings.append(finding)
            return

        if finding.severity.rank > existing.severity.rank:
            existing.severity = finding.severity
        if _CONFIDENCE_RANK.get(finding.confidence, 0) > _CONFIDENCE_RANK.get(existing.confidence, 0):
            existing.confidence = finding.confidence
        for ref in finding.references:
            if ref not in existing.references:
                existing.references.append(ref)
        if finding.confirmed:
            existing.confirmed = True
        if finding.poc and not existing.poc:
            existing.poc = finding.poc
        merged = existing.metadata.setdefault("merged_detectors", [existing.detector])
        if finding.detector not in merged:
            merged.append(finding.detector)
        existing.metadata["merged_count"] = existing.metadata.get("merged_count", 1) + 1

    def extend(self, findings: list[Finding]) -> None:
        for f in findings:
            self.add(f)

    def counts(self) -> dict[str, int]:
        out = {s.value: 0 for s in Severity}
        for f in self.findings:
            out[f.severity.value] += 1
        return out

    @property
    def risk_score(self) -> int:
        """0-100 risk score. Saturating sum of severity weights."""
        raw = sum(f.severity.weight for f in self.findings)
        return min(100, raw)

    @property
    def risk_band(self) -> str:
        s = self.risk_score
        return "CRITICAL" if s >= 85 else "HIGH" if s >= 70 else "MEDIUM" if s >= 45 else "LOW"

    @property
    def risk_band_color(self) -> str:
        s = self.risk_score
        return "#8B0000" if s >= 70 else "#8B4513" if s >= 45 else "#B8860B"

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (-f.severity.rank, f.title))

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "phase": self.phase,
            "risk_score": self.risk_score,
            "risk_band": self.risk_band,
            "counts": self.counts(),
            "dedup_merged": sum(1 for f in self.findings if f.metadata.get("merged_count", 1) > 1),
            "codebase_map": self.codebase_map.to_dict() if self.codebase_map else None,
            "findings": [f.to_dict() for f in self.sorted_findings()],
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "llm_provider": self.llm_provider,
            "errors": self.errors,
        }
