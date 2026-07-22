"""Tests for secret detection: entropy, known formats, masking, placeholders."""

from __future__ import annotations

from argus.scanner.secrets import scan_secrets, shannon_entropy, _mask


def test_shannon_entropy_ranges():
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaaaaaa") < 1.0
    assert shannon_entropy("aB3$xZ9kLp2qWm7n") > 3.0


def test_detects_aws_and_stripe(vuln_repo):
    findings = scan_secrets(vuln_repo)
    titles = " ".join(f.title for f in findings)
    assert "AWS Access Key ID" in titles
    assert "Stripe Live Secret Key" in titles


def test_masking_hides_token_body():
    token = "AKIA" + "IOSFODNN7EXAMPLE"
    masked = _mask(f"key = {token}")
    assert token not in masked
    assert "•" in masked


def test_placeholder_not_flagged(tmp_path):
    f = tmp_path / "conf.py"
    f.write_text("password = 'your_password_here'\napi_key = 'changeme'\n", encoding="utf-8")
    findings = scan_secrets(tmp_path)
    generic = [x for x in findings if "Generic Secret" in x.title]
    assert generic == []


def test_db_connection_string_placeholder_not_flagged(tmp_path):
    # Reported from a real report: postgresql://USER:PASSWORD@HOST — a common
    # README/.env.example convention (the value IS the field's own name, no
    # <angle brackets>, no "your_"/"example" wording) — was flagged as a real
    # hardcoded "DB Connection String w/ creds", both in the working tree and
    # (worse) in "secrets in git history", on a target with no real secret at
    # all.
    f = tmp_path / ".env"
    f.write_text('DATABASE_URL="postgresql://USER:PASSWORD@HOST:6543/postgres?pgbouncer=true"\n', encoding="utf-8")
    findings = scan_secrets(tmp_path)
    assert not any("DB Connection String" in x.title for x in findings)


def test_db_connection_string_real_creds_still_flagged(tmp_path):
    f = tmp_path / ".env"
    f.write_text('DATABASE_URL="postgresql://admin:Tr0ub4dor3xyz@db.prod.internal:5432/app"\n', encoding="utf-8")
    findings = scan_secrets(tmp_path)
    assert any("DB Connection String" in x.title for x in findings)


def test_real_generic_secret_flagged(tmp_path):
    f = tmp_path / "conf.py"
    f.write_text("password = 'Tr0ub4dor&3xKqun'\n", encoding="utf-8")
    findings = scan_secrets(tmp_path)
    assert any("Generic Secret" in x.title for x in findings)


def test_detects_modern_token_formats(tmp_path):
    # Fake-but-format-valid tokens built by concatenation so no complete
    # secret literal is committed (GitHub push protection would flag it).
    tokens = {
        "npm Access Token": "npm_" + "A" * 36,
        "PyPI Upload Token": "pypi-AgE" + "B" * 55,
        "HashiCorp Vault Token": "hvs." + "C" * 30,
        "DigitalOcean PAT": "dop_v1_" + "a" * 64,
        "Shopify Access Token": "shpat_" + "a" * 32,
    }
    lines = [f"key{i} = '{tok}'" for i, tok in enumerate(tokens.values())]
    (tmp_path / "creds.env").write_text("\n".join(lines) + "\n", encoding="utf-8")
    titles = " ".join(f.title for f in scan_secrets(tmp_path))
    for label in tokens:
        assert label in titles, f"{label} not detected"


def test_modern_token_patterns_ignore_benign_text(tmp_path):
    (tmp_path / "readme.md").write_text(
        "Run npm install then dapper up. Visit https://example.com for docs.\n",
        encoding="utf-8",
    )
    findings = scan_secrets(tmp_path)
    labels = {f.title for f in findings}
    for label in ("npm Access Token", "Databricks Token", "HashiCorp Vault Token"):
        assert label not in labels


def test_entropy_skipped_in_lockfile_but_pattern_still_fires(tmp_path):
    # package-lock.json is full of integrity hashes (entropy noise) — the entropy
    # pass is skipped there, but a real key pattern is still caught.
    lock = tmp_path / "package-lock.json"
    lock.write_text(
        '{"a": {"integrity": "sha512-' + "AbCdEf0123456789+/ZzYyXxWwVvUuTtSsRrQqPpOoNnMmLlKk012345678==" + '"},\n'
        ' "b": {"key": "AKIA' + "IOSFODNN7EXAMPLE" + '"}}\n', encoding="utf-8")
    findings = scan_secrets(tmp_path)
    dets = {(f.detector, f.title) for f in findings}
    assert not any(d == "secrets-entropy" for d, _ in dets)          # noise gone
    assert any("AWS Access Key ID" in t for _, t in dets)             # real key kept


def test_entropy_skipped_in_minified_and_vendored(tmp_path):
    (tmp_path / "app.min.js").write_text(
        "var x='" + "Zx9Kd82hFmQp04SsRrTtUuVvWwXxYyZz+/AbCd" + "';\n", encoding="utf-8")
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "bundle.js").write_text(
        "const k='" + "9f8e7d6c5b4a32100011223344556677AbCdEf" + "';\n", encoding="utf-8")
    findings = [f for f in scan_secrets(tmp_path) if f.detector == "secrets-entropy"]
    assert findings == []


def test_hash_length_hex_token_not_flagged_as_entropy(tmp_path):
    # a bare md5 (32) / sha1 (40) / sha256 (64) hex digest is a checksum, not a secret
    (tmp_path / "seed.sql").write_text(
        "INSERT INTO u VALUES ('" + "5f4dcc3b5aa765d61d8327deb882cf99" + "');\n", encoding="utf-8")
    findings = [f for f in scan_secrets(tmp_path) if f.detector == "secrets-entropy"]
    assert findings == []


def test_entropy_still_fires_in_normal_source(tmp_path):
    # regression guard: a genuine unknown-format high-entropy secret in real code
    # must still be caught.
    (tmp_path / "cfg.py").write_text(
        "SESSION_KEY = '" + "kJ8xQ2mZ9pR4vT7wY0aB3cD6eF1gH5iN" + "'\n", encoding="utf-8")
    findings = [f for f in scan_secrets(tmp_path)
                if f.detector in ("secrets", "secrets-entropy")]
    assert findings, "a real high-entropy secret in normal source should still be flagged"


def test_db_connection_string_placeholder_username_only_still_flags_real_password(tmp_path):
    # A real bug found by review of the original fix: the placeholder check
    # used OR logic — either side being placeholder-shaped suppressed the
    # WHOLE finding. A genuinely random, real password paired with a merely
    # commonplace username (here "token") must still be caught.
    f = tmp_path / "conf.py"
    f.write_text('url = "mongodb://token:8f3Kd9QpL2xVbN7mRt5Wc@cluster0.example.net:27017/prod"\n', encoding="utf-8")
    findings = scan_secrets(tmp_path)
    assert any("DB Connection String" in x.title for x in findings)


def test_db_connection_string_templating_placeholders_not_flagged(tmp_path):
    # ${VAR}, {{var}}, and %VAR% are just as common a .env.example/
    # docker-compose placeholder convention as bare USER:PASSWORD.
    f = tmp_path / ".env"
    f.write_text(
        'A="postgresql://${DB_USER}:${DB_PASS}@host:5432/db"\n'
        'B="mysql://{{username}}:{{password}}@host/db"\n'
        'C="mysql://%DB_USER%:%DB_PASS%@host/db"\n',
        encoding="utf-8",
    )
    findings = scan_secrets(tmp_path)
    assert not any("DB Connection String" in x.title for x in findings)


def test_generic_secret_on_a_long_minified_style_line_still_flagged(tmp_path):
    # A minified/bundled JS file is often one line covering the whole file —
    # the high-confidence regex patterns must still run on it; only the
    # (separate, cheaper-to-skip) entropy pass has a low length cutoff.
    padding = "var x=1;" * 600  # well past the old 4000-char cutoff
    f = tmp_path / "bundle.js"
    f.write_text(padding + ' var k="AKIAIOSFODNN7EXAMPLE";' + padding, encoding="utf-8")
    findings = scan_secrets(tmp_path)
    assert any("AWS Access Key ID" in x.title for x in findings)


def _init_test_repo(tmp_path):
    from git import Repo
    repo_dir = tmp_path / "gitrepo"
    repo = Repo.init(str(repo_dir), initial_branch="main")
    repo.config_writer().set_value("user", "email", "t@t.co").release()
    repo.config_writer().set_value("user", "name", "t").release()
    return repo_dir, repo


def test_git_history_catches_a_committed_then_removed_generic_secret(tmp_path):
    # scan_git_history previously had zero test coverage at all, and a real
    # bug: "Generic Secret Assignment" was silently excluded from history
    # scanning with no comment explaining why — defeating the function's own
    # stated purpose (its docstring: "secrets removed in later commits still
    # live in history") for exactly a plain `password = "..."` committed then
    # reverted, the single most common "oops" shape.
    from argus.scanner.secrets import scan_git_history

    repo_dir, repo = _init_test_repo(tmp_path)
    f = repo_dir / "conf.py"
    f.write_text("password = 'Tr0ub4dor&3xKqun'\n", encoding="utf-8")
    repo.index.add(["conf.py"])
    repo.index.commit("oops, committed a real secret")
    f.write_text("password = os.environ['APP_PASSWORD']\n", encoding="utf-8")
    repo.index.add(["conf.py"])
    repo.index.commit("fix: move secret to env var")

    findings = scan_git_history(repo_dir)
    assert any("Generic Secret" in f.title for f in findings)


def test_git_history_does_not_flag_a_placeholder_generic_secret(tmp_path):
    from argus.scanner.secrets import scan_git_history

    repo_dir, repo = _init_test_repo(tmp_path)
    f = repo_dir / "conf.py"
    f.write_text("password = 'changeme'\n", encoding="utf-8")
    repo.index.add(["conf.py"])
    repo.index.commit("initial")

    findings = scan_git_history(repo_dir)
    assert not any("Generic Secret" in f.title for f in findings)


def test_git_history_still_catches_a_committed_then_removed_aws_key(tmp_path):
    from argus.scanner.secrets import scan_git_history

    repo_dir, repo = _init_test_repo(tmp_path)
    f = repo_dir / "conf.py"
    f.write_text('AWS_KEY = "AKIA' + 'IOSFODNN7EXAMPLE' + '"\n', encoding="utf-8")
    repo.index.add(["conf.py"])
    repo.index.commit("oops")
    f.write_text("AWS_KEY = os.environ['AWS_KEY']\n", encoding="utf-8")
    repo.index.add(["conf.py"])
    repo.index.commit("fix")

    findings = scan_git_history(repo_dir)
    assert any("AWS Access Key ID" in f.title for f in findings)
