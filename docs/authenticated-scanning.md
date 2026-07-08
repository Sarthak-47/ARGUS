# Authenticated Scanning

Most real apps hide their interesting surface behind a login. An
unauthenticated scan only ever sees the doormat. This guide covers every way
to give Argus a real session, from simplest to most involved.

Config lives in a `.argus-auth.toml` file — auto-discovered in the working
directory, or passed explicitly with `--auth <file>`. **Keep it out of version
control** (add it to `.gitignore`); a full template with every option is at
[`.argus-auth.example.toml`](../.argus-auth.example.toml).

```bash
argus attack --url http://localhost:3000 --auth .argus-auth.toml
argus audit /path/to/repo --auth .argus-auth.toml
```

Because every attack agent — and ReconBot's crawl — issues requests through
one shared HTTP client, applying auth once means the **whole 18-agent swarm**
acts as the logged-in user. Credentials are never echoed into a captured
proof-of-concept; the `Authorization`/`Cookie` headers are redacted.

## Static credentials

The simplest case — you already have a token or session cookie.

```toml
bearer = "eyJhbGciOi..."           # shorthand for an Authorization header

[headers]
X-API-Key = "..."

[cookies]
session = "..."

[basic]
username = "admin"
password = "s3cret"
```

These compose — set as many as you need.

## Form login

POST credentials to a login URL; Argus reuses whatever session cookie the
response sets.

```toml
[login]
url = "http://localhost:3000/api/login"
method = "POST"
json = true                 # form-encoded by default; set true for a JSON body
[login.data]
email = "admin@example.com"
password = "s3cret"
```

If the login endpoint returns a bearer token in JSON instead of (or alongside)
a cookie, extract it with a dotted path into the response:

```toml
[login]
url = "http://localhost:3000/api/login"
token_json_path = "data.token"   # e.g. {"data": {"token": "eyJ..."}}
[login.data]
email = "admin@example.com"
password = "s3cret"
```

## CSRF-protected login forms

Many real login forms (DVWA's included) embed a rotating hidden token that
must be echoed back in the POST or the login is rejected. Set `csrf_field` to
the input's `name` attribute and Argus GETs the login page first to scrape its
current `value`:

```toml
[login]
url = "http://localhost/login.php"
csrf_field = "user_token"
[login.data]
username = "admin"
password = "password"
Login = "Login"
```

## A post-login "unlock" step

Some apps need one more request after login before the session is actually
usable — a security-level toggle, a tenant/organization picker, accepting
terms. It runs on the *same* authenticated session, right after login:

```toml
[login]
url = "http://localhost/login.php"
csrf_field = "user_token"
post_login_url = "http://localhost/security.php"
[login.data]
username = "admin"
password = "password"
[login.post_login_data]
security = "low"
```

(This exact example is DVWA's own pattern — its vulnerable pages are patched
at "impossible" difficulty per-session until you separately lower it.)

## OAuth2 client-credentials

```toml
[oauth2]
token_url = "http://localhost:3000/oauth/token"
client_id = "..."
client_secret = "..."
scope = "read write"        # optional
```

Fetches an access token once and uses it as a Bearer token for the whole run.

## Testing authorization with a second identity

Add `--auth-b <file>` (a second `.argus-auth.toml`, ideally a **lower-privilege**
account) and Argus additionally tests **broken object- and function-level
authorization** — BOLA/BFLA, the #1 API risk:

```bash
argus attack --url http://localhost:3000 --auth admin-auth.toml --auth-b user-auth.toml
```

The AuthzTester agent compares three actors per candidate endpoint —
anonymous, identity A, identity B — and flags only the
protected-from-anonymous-yet-reachable-by-a-different-user pattern: an object a
second authenticated user can read that anonymous can't (BOLA), or a
privileged-looking route (`/admin/...`) an ordinary user can reach (BFLA).
Public endpoints never trigger a false positive because the anonymous baseline
has to fail first.

## Troubleshooting

- **"Login to ... returned HTTP 4xx — check credentials."** The login request
  itself failed. Double-check the URL, field names, and whether the app
  expects JSON (`json = true`) vs. form-encoded.
- **"has no hidden input named 'X'"** — the `csrf_field` name doesn't match
  what's actually in the login page's HTML. View the page source and check the
  exact `name="..."` attribute.
- **Findings don't improve after adding auth** — some apps need more than
  login (see the post-login step above). Check whether the app has a
  session-level "difficulty"/feature-flag setting that needs toggling after
  login, the same way DVWA does.
