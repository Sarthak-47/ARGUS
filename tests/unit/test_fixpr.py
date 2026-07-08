"""Tests for the auto-fix-PR machinery (argus/fixpr.py).

These exercise the real git plumbing (branch/commit/push) against a throwaway
local "remote" repo — never a real GitHub remote — and the safety gates that
must refuse before any of that runs. `gh pr create` itself (which needs real
GitHub auth) is only exercised via its failure path (gh absent/unauthenticated),
never actually invoked against github.com.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from git import Repo

from argus.fix import AppliedFix
from argus.fixpr import (
    PrError,
    commit_and_push_fixes,
    ensure_clean_repo,
    github_auth_available,
    open_pull_request,
)


def _init_repo_with_remote(tmp_path: Path) -> Repo:
    """A local repo with a bare 'origin' remote (a throwaway local path, not
    GitHub) so push actually succeeds without touching the network."""
    bare = tmp_path / "origin.git"
    Repo.init(str(bare), bare=True)

    work = tmp_path / "work"
    repo = Repo.init(str(work))
    repo.config_writer().set_value("user", "email", "t@t.co").release()
    repo.config_writer().set_value("user", "name", "t").release()
    (work / "app.py").write_text("def f():\n    return 1\n", encoding="utf-8")
    repo.index.add(["app.py"])
    repo.index.commit("initial")
    repo.create_remote("origin", str(bare))
    repo.git.push("--set-upstream", "origin", repo.active_branch.name)
    return repo


def test_ensure_clean_repo_rejects_dirty_tree(tmp_path: Path):
    repo = _init_repo_with_remote(tmp_path)
    (Path(repo.working_dir) / "app.py").write_text("def f():\n    return 2\n", encoding="utf-8")
    with pytest.raises(PrError, match="uncommitted changes"):
        ensure_clean_repo(Path(repo.working_dir))


def test_ensure_clean_repo_rejects_untracked_files(tmp_path: Path):
    repo = _init_repo_with_remote(tmp_path)
    (Path(repo.working_dir) / "new.py").write_text("x = 1\n", encoding="utf-8")
    with pytest.raises(PrError, match="uncommitted changes"):
        ensure_clean_repo(Path(repo.working_dir))


def test_ensure_clean_repo_rejects_no_git_repo(tmp_path: Path):
    plain = tmp_path / "not_a_repo"
    plain.mkdir()
    with pytest.raises(PrError, match="not inside a git repository"):
        ensure_clean_repo(plain)


def test_ensure_clean_repo_rejects_detached_head(tmp_path: Path):
    repo = _init_repo_with_remote(tmp_path)
    repo.git.checkout(repo.head.commit.hexsha)  # detach
    with pytest.raises(PrError, match="detached HEAD"):
        ensure_clean_repo(Path(repo.working_dir))


def test_ensure_clean_repo_rejects_no_origin(tmp_path: Path):
    work = tmp_path / "no_remote"
    repo = Repo.init(str(work))
    repo.config_writer().set_value("user", "email", "t@t.co").release()
    repo.config_writer().set_value("user", "name", "t").release()
    (work / "app.py").write_text("x = 1\n", encoding="utf-8")
    repo.index.add(["app.py"])
    repo.index.commit("initial")
    with pytest.raises(PrError, match="no 'origin' remote"):
        ensure_clean_repo(work)


def test_ensure_clean_repo_accepts_clean_tree(tmp_path: Path):
    repo = _init_repo_with_remote(tmp_path)
    result = ensure_clean_repo(Path(repo.working_dir))
    assert result.working_dir == repo.working_dir


def test_commit_and_push_creates_branch_and_pushes(tmp_path: Path):
    repo = _init_repo_with_remote(tmp_path)
    base = repo.active_branch.name
    # Simulate a fix already having been written to disk by apply_fixes().
    (Path(repo.working_dir) / "app.py").write_text("def f():\n    return 2  # fixed\n", encoding="utf-8")
    applied = [AppliedFix(finding_id="f1", file="app.py", explanation="fixed the bug",
                          diff="", written=True)]

    branch = commit_and_push_fixes(repo, applied, branch="argus/test-branch")

    assert branch == "argus/test-branch"
    assert repo.active_branch.name == branch
    # The commit landed and the branch exists on the "remote".
    remote_refs = [r.name for r in repo.remotes.origin.refs]
    assert f"origin/{branch}" in remote_refs
    assert base != branch


def test_commit_and_push_refuses_when_nothing_written(tmp_path: Path):
    repo = _init_repo_with_remote(tmp_path)
    applied = [AppliedFix(finding_id="f1", file="app.py", explanation="x", diff="", written=False)]
    with pytest.raises(PrError, match="nothing to commit"):
        commit_and_push_fixes(repo, applied)


def test_open_pull_request_without_gh_cli_reports_branch_pushed(tmp_path: Path, monkeypatch):
    import argus.fixpr as fixpr_mod

    monkeypatch.setattr(fixpr_mod.shutil, "which", lambda _: None)
    applied = [AppliedFix(finding_id="f1", file="app.py", explanation="x", diff="", written=True)]
    result = open_pull_request(tmp_path, "argus/test-branch", "main", applied)
    assert result.url is None
    assert "gh` CLI isn't installed" in result.note


def test_github_auth_available_true_with_env_token(monkeypatch):
    monkeypatch.setenv("GH_TOKEN", "x")
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    assert github_auth_available() is True


def test_github_auth_available_false_without_gh_or_token(monkeypatch):
    import argus.fixpr as fixpr_mod

    monkeypatch.delenv("GH_TOKEN", raising=False)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.setattr(fixpr_mod.shutil, "which", lambda _: None)
    assert github_auth_available() is False
