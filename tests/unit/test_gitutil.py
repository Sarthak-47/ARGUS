"""Tests for diff-aware git helpers."""

from __future__ import annotations

import pytest

from argus.gitutil import GitError, changed_files


def _init_repo(path):
    from git import Repo

    repo = Repo.init(str(path), initial_branch="main")
    repo.config_writer().set_value("user", "email", "t@t.co").release()
    repo.config_writer().set_value("user", "name", "t").release()
    return repo


def test_changed_files_reports_new_file_on_branch(tmp_path):
    repo = _init_repo(tmp_path)
    (tmp_path / "old.py").write_text("x = 1\n", encoding="utf-8")
    repo.index.add(["old.py"])
    repo.index.commit("base")

    repo.git.checkout("-b", "feature")
    (tmp_path / "new.py").write_text("y = 2\n", encoding="utf-8")
    repo.index.add(["new.py"])
    repo.index.commit("feat")

    changed = changed_files(tmp_path, "main")
    assert "new.py" in changed
    assert "old.py" not in changed  # unchanged since the merge-base


def test_changed_files_includes_uncommitted_and_untracked(tmp_path):
    repo = _init_repo(tmp_path)
    (tmp_path / "old.py").write_text("x = 1\n", encoding="utf-8")
    repo.index.add(["old.py"])
    repo.index.commit("base")

    # Uncommitted modification + a brand-new untracked file.
    (tmp_path / "old.py").write_text("x = 2\n", encoding="utf-8")
    (tmp_path / "fresh.py").write_text("z = 3\n", encoding="utf-8")

    changed = changed_files(tmp_path, "main")
    assert "old.py" in changed
    assert "fresh.py" in changed


def test_changed_files_bad_ref_raises_giterror(tmp_path):
    repo = _init_repo(tmp_path)
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    repo.index.add(["a.py"])
    repo.index.commit("base")

    with pytest.raises(GitError):
        changed_files(tmp_path, "no-such-ref")


def test_changed_files_not_a_repo_raises_giterror(tmp_path):
    with pytest.raises(GitError):
        changed_files(tmp_path, "main")
