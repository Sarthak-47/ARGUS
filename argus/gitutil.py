"""Git helpers — currently: the set of files changed vs a base ref.

Used by diff-aware scanning (`argus scan --diff-base main`), the standard
PR-gate model: only surface findings in files this branch actually touched,
so a huge pre-existing backlog doesn't drown out (or fail CI on) what the
current change introduced.
"""

from __future__ import annotations

from pathlib import Path


class GitError(RuntimeError):
    """Raised when a git operation can't be completed."""


def changed_files(repo_root: Path, base_ref: str) -> set[str]:
    """Return repo-relative paths (forward slashes) changed between ``base_ref``
    and the working tree.

    Uses the three-dot form ``base...`` semantics via a merge-base diff so it
    reflects "what this branch changed relative to base", not unrelated commits
    that landed on base meanwhile — the same thing a PR diff shows. Includes
    uncommitted working-tree changes too, so it's useful locally before a commit.
    """
    try:
        from git import GitCommandError, InvalidGitRepositoryError, Repo
    except ImportError as exc:  # pragma: no cover - GitPython is a hard dep
        raise GitError(f"GitPython not available: {exc}") from exc

    try:
        repo = Repo(str(repo_root), search_parent_directories=True)
    except InvalidGitRepositoryError as exc:
        raise GitError(f"{repo_root} is not inside a git repository.") from exc

    try:
        merge_base = repo.git.merge_base(base_ref, "HEAD").strip()
    except GitCommandError as exc:
        raise GitError(
            f"Could not resolve base ref '{base_ref}' (does it exist?): {(exc.stderr or '').strip()}"
        ) from exc

    changed: set[str] = set()
    # Committed changes since the merge-base, plus anything modified/staged now.
    for diff_target in (merge_base, None):
        try:
            args = ["--name-only", diff_target] if diff_target else ["--name-only", "HEAD"]
            out = repo.git.diff(*args)
        except GitError:
            continue
        for line in out.splitlines():
            line = line.strip()
            if line:
                changed.add(line.replace("\\", "/"))
    # Untracked files (a brand-new file in the branch).
    for path in repo.untracked_files:
        changed.add(path.replace("\\", "/"))
    return changed
