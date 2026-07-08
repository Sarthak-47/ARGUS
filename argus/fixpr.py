"""Auto-fix pull requests (roadmap v0.5.1).

``argus fix <path> --apply --pr`` takes the already-validated, reverified
patches one step further: commit them to a new branch, push it, and open a
real GitHub pull request with the finding + explanation in the description —
so remediation lands where developers actually work instead of sitting in a
local diff.

This touches real, shared state (a new branch and a PR on your repo), so it is
opt-in (``--pr`` is never implied by ``--apply``) and requires you to already
have GitHub authentication configured — Argus never tries to acquire
credentials on your behalf. Either:
  - the `gh` CLI installed and logged in (``gh auth login``), or
  - a ``GH_TOKEN`` / ``GITHUB_TOKEN`` environment variable set.

The working tree must be clean *before* Argus applies its patches — a
pre-existing dirty state would otherwise get swept into the fix commit.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from argus.fix import AppliedFix


class PrError(RuntimeError):
    """Raised when the git/PR flow can't proceed."""


@dataclass
class OpenedPr:
    branch: str
    url: str | None
    note: str


def github_auth_available() -> bool:
    """True if a `gh` CLI is installed and logged in, or a GitHub token env var
    is set — either satisfies `gh pr create`'s auth requirement."""
    if os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN"):
        return True
    if shutil.which("gh") is None:
        return False
    try:
        proc = subprocess.run(["gh", "auth", "status"], capture_output=True, text=True, timeout=15)
        return proc.returncode == 0
    except (subprocess.SubprocessError, OSError):
        return False


def ensure_clean_repo(root: Path):
    """Open the repo at ``root`` and verify the working tree is clean and on a
    real branch. Returns the opened ``git.Repo``."""
    try:
        from git import InvalidGitRepositoryError, Repo
    except ImportError as exc:  # pragma: no cover - GitPython is a hard dep
        raise PrError(f"GitPython not available: {exc}") from exc

    try:
        repo = Repo(str(root), search_parent_directories=True)
    except InvalidGitRepositoryError as exc:
        raise PrError(f"{root} is not inside a git repository — --pr needs a real git repo.") from exc

    if repo.head.is_detached:
        raise PrError("Repo is in a detached HEAD state — check out a branch first.")
    if repo.is_dirty(untracked_files=True):
        raise PrError(
            "Working tree has uncommitted changes — commit or stash them first, "
            "so the fix branch/PR contains only Argus's patch."
        )
    if "origin" not in [r.name for r in repo.remotes]:
        raise PrError("Repo has no 'origin' remote to push the fix branch to.")
    return repo


def commit_and_push_fixes(repo, applied: list[AppliedFix], *, branch: str | None = None) -> str:
    """Create a branch off the current HEAD, commit the applied fixes, and push
    it to origin. Returns the branch name. Rolls back the local branch (never
    the base branch itself) if committing fails."""
    from git import GitCommandError

    written = [a for a in applied if a.written]
    if not written:
        raise PrError("No fixes were actually written — nothing to commit.")

    base = repo.active_branch.name
    name = branch or f"argus/auto-fix-{int(time.time())}"
    try:
        repo.git.checkout("-b", name)
    except GitCommandError as exc:
        raise PrError(f"Could not create branch '{name}': {(exc.stderr or '').strip()}") from exc

    try:
        for a in written:
            repo.git.add(a.file)
        message = (
            f"fix: Argus auto-fix — {len(written)} finding(s)\n\n"
            + "\n".join(f"- {a.file}: {a.explanation}" for a in written)
        )
        repo.git.commit("-m", message)
    except GitCommandError as exc:
        repo.git.checkout(base)
        repo.git.branch("-D", name)
        raise PrError(f"Could not commit fixes: {(exc.stderr or '').strip()}") from exc

    try:
        repo.git.push("--set-upstream", "origin", name)
    except GitCommandError as exc:
        # The commit is safe locally on `name`; only the push failed (likely an
        # auth/permission issue) — don't discard the work, just report it.
        raise PrError(
            f"Fixes were committed locally on branch '{name}', but the push to origin "
            f"failed: {(exc.stderr or '').strip()}. Push it yourself once you have access: "
            f"git push --set-upstream origin {name}"
        ) from exc
    return name


def open_pull_request(root: Path, branch: str, base: str, applied: list[AppliedFix]) -> OpenedPr:
    """Open a GitHub PR for ``branch`` -> ``base`` via the `gh` CLI, with a body
    describing each fixed finding."""
    written = [a for a in applied if a.written]
    if shutil.which("gh") is None:
        return OpenedPr(branch=branch, url=None,
                         note="Branch pushed, but the `gh` CLI isn't installed — "
                              f"open the PR yourself: {branch} -> {base}, or install gh and retry.")

    body_lines = ["Automated fixes generated and reverified by "
                  "[Argus](https://github.com/Sarthak-47/ARGUS).", ""]
    for a in written:
        body_lines.append(f"### `{a.file}`")
        body_lines.append(a.explanation)
        body_lines.append("")
    body = "\n".join(body_lines)
    title = f"fix: Argus auto-fix — {len(written)} finding(s)"

    try:
        proc = subprocess.run(
            ["gh", "pr", "create", "--base", base, "--head", branch, "--title", title, "--body", body],
            cwd=str(root), capture_output=True, text=True, timeout=60,
        )
    except (subprocess.SubprocessError, OSError) as exc:
        return OpenedPr(branch=branch, url=None, note=f"Branch pushed, but `gh pr create` failed to run: {exc}")

    if proc.returncode != 0:
        return OpenedPr(branch=branch, url=None,
                         note=f"Branch pushed, but `gh pr create` failed: {(proc.stderr or proc.stdout).strip()}")
    lines = [ln.strip() for ln in (proc.stdout or "").splitlines() if ln.strip()]
    url = lines[-1] if lines else None
    return OpenedPr(branch=branch, url=url, note="Pull request opened.")
