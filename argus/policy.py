"""Policy-as-code CI gating — per-rule/per-category pass/warn/fail control.

``--fail-on <severity>`` is a single global threshold: fail if anything at or
above one severity exists. That's coarse — a team often wants to *fail* on any
confirmed SQLi but only *warn* on missing security headers, regardless of the
raw severity bucket. A policy file expresses that.

Policy file (TOML, default name ``.argus-policy.toml`` at the repo root, or an
explicit path via ``--policy``)::

    # Action for findings no rule below matches. fail | warn | ignore
    default = "warn"

    # Rules are evaluated top to bottom; the FIRST match decides the action.
    # A rule matches when every field it specifies matches the finding
    # (fields are ANDed); omit a field to leave it unconstrained.
    [[rules]]
    severity = "critical"
    action = "fail"

    [[rules]]
    category = "injection"
    action = "fail"

    [[rules]]
    confirmed = true          # an attack agent actually proved it
    action = "fail"

    [[rules]]
    detector = "secrets-entropy"   # noisy heuristic — never block CI on it
    action = "ignore"

``fail`` findings make ``argus scan --policy ...`` exit non-zero (CI gate);
``warn`` findings are reported but don't fail the build; ``ignore`` findings
are counted but excluded from the gate decision entirely.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - 3.10 fallback
    import tomli as tomllib  # type: ignore

from argus.models import Finding

_VALID_ACTIONS = ("fail", "warn", "ignore")
DEFAULT_POLICY_FILENAME = ".argus-policy.toml"


class PolicyError(ValueError):
    """Raised when a policy file is malformed."""


@dataclass
class PolicyRule:
    action: str
    severity: str | None = None
    category: str | None = None
    detector: str | None = None
    confirmed: bool | None = None

    def matches(self, f: Finding) -> bool:
        if self.severity is not None and f.severity.value.lower() != self.severity.lower():
            return False
        if self.category is not None and f.category.lower() != self.category.lower():
            return False
        if self.detector is not None and not f.detector.lower().startswith(self.detector.lower()):
            return False
        if self.confirmed is not None and f.confirmed != self.confirmed:
            return False
        return True


@dataclass
class Policy:
    default: str = "warn"
    rules: list[PolicyRule] = field(default_factory=list)

    def action_for(self, f: Finding) -> str:
        """First matching rule wins; falls back to ``default``."""
        for rule in self.rules:
            if rule.matches(f):
                return rule.action
        return self.default


def _coerce_action(value, where: str) -> str:
    action = str(value).lower()
    if action not in _VALID_ACTIONS:
        raise PolicyError(f"{where}: action must be one of {_VALID_ACTIONS}, got {value!r}")
    return action


def parse_policy(data: dict) -> Policy:
    default = _coerce_action(data.get("default", "warn"), "default")
    rules: list[PolicyRule] = []
    raw_rules = data.get("rules", [])
    if not isinstance(raw_rules, list):
        raise PolicyError("'rules' must be a list of tables")
    for i, raw in enumerate(raw_rules):
        if not isinstance(raw, dict):
            raise PolicyError(f"rules[{i}] must be a table")
        if "action" not in raw:
            raise PolicyError(f"rules[{i}] is missing 'action'")
        rules.append(PolicyRule(
            action=_coerce_action(raw["action"], f"rules[{i}]"),
            severity=raw.get("severity"),
            category=raw.get("category"),
            detector=raw.get("detector"),
            confirmed=raw.get("confirmed"),
        ))
    return Policy(default=default, rules=rules)


def load_policy(path: Path) -> Policy:
    try:
        with path.open("rb") as fh:
            data = tomllib.load(fh)
    except OSError as exc:
        raise PolicyError(f"could not read policy file {path}: {exc}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise PolicyError(f"invalid TOML in policy file {path}: {exc}") from exc
    return parse_policy(data)


def find_default_policy(target: str) -> Path | None:
    """A ``.argus-policy.toml`` sitting in a local target dir is auto-applied."""
    p = Path(target).expanduser()
    if p.is_file():
        p = p.parent
    candidate = p / DEFAULT_POLICY_FILENAME
    return candidate if candidate.is_file() else None


@dataclass
class PolicyOutcome:
    failing: list[Finding]
    warning: list[Finding]
    ignored: list[Finding]

    @property
    def should_fail(self) -> bool:
        return bool(self.failing)


def evaluate(policy: Policy, findings: list[Finding]) -> PolicyOutcome:
    failing: list[Finding] = []
    warning: list[Finding] = []
    ignored: list[Finding] = []
    for f in findings:
        action = policy.action_for(f)
        if action == "fail":
            failing.append(f)
        elif action == "warn":
            warning.append(f)
        else:
            ignored.append(f)
    return PolicyOutcome(failing=failing, warning=warning, ignored=ignored)
