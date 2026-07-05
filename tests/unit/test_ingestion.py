"""Tests for git-clone failure handling in ingestion.

Regression coverage for two real bugs found via live testing against actual
dead/nonexistent repo URLs: the raw GitCommandError dumped the full command
invocation (unreadable for a CLI user) instead of git's actual "repository
not found" reason, and the temp directory created for the clone was left
behind on disk when the clone failed.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
from git import GitCommandError

from argus.scanner.ingestion import _clone


def _raise_not_found(*args, **kwargs):
    raise GitCommandError(
        ["git", "clone"],
        128,
        stderr=(
            "\n  stderr: 'Cloning into 'C:\\tmp\\argus-xyz'...\n"
            "remote: Repository not found.\n"
            "fatal: repository 'https://github.com/nope/nope.git/' not found\n'"
        ),
    )


def test_clone_failure_raises_friendly_message_not_raw_dump():
    with patch("git.Repo.clone_from", side_effect=_raise_not_found):
        with pytest.raises(RuntimeError) as exc_info:
            _clone("https://github.com/nope/nope.git")

    message = str(exc_info.value)
    assert "fatal: repository" in message
    assert "not found" in message
    # the noisy parts of the raw exception must not leak into the message
    assert "cmdline" not in message.lower()
    assert "Cloning into" not in message


def test_clone_failure_cleans_up_temp_dir():
    created: list[Path] = []
    real_mkdtemp = __import__("tempfile").mkdtemp

    def _tracking_mkdtemp(*args, **kwargs):
        d = real_mkdtemp(*args, **kwargs)
        created.append(Path(d))
        return d

    with patch("tempfile.mkdtemp", side_effect=_tracking_mkdtemp):
        with patch("git.Repo.clone_from", side_effect=_raise_not_found):
            with pytest.raises(RuntimeError):
                _clone("https://github.com/nope/nope.git")

    assert created, "mkdtemp should have been called"
    assert not created[0].exists(), "temp clone dir must be cleaned up on failure"
