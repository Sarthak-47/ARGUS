// Shared behavior across every page — safe to include everywhere; each piece
// no-ops if its target element isn't on the current page.

function copyInstall(el){
  const text = el.querySelector('span').textContent;
  navigator.clipboard?.writeText(text);
  const label = el.querySelector('.copy');
  const prev = label.textContent;
  label.textContent = 'COPIED';
  setTimeout(() => { label.textContent = prev; }, 1400);
}

// ---- mobile nav -----------------------------------------------------------
(function mobileNav(){
  const toggle = document.querySelector('.nav-toggle');
  const links = document.querySelector('nav .links');
  if (!toggle || !links) return;
  toggle.addEventListener('click', () => {
    const open = links.classList.toggle('open');
    toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
  });
  links.querySelectorAll('a').forEach(a => a.addEventListener('click', () => {
    links.classList.remove('open');
    toggle.setAttribute('aria-expanded', 'false');
  }));
})();

// ---- OS-aware download CTA -------------------------------------------------
// Detects the visitor's platform and tailors the primary download button's
// label (and, on the download page, which OS card is marked "recommended")
// — still links to /releases/latest either way, since a specific asset
// filename bakes in the version number and would go stale next release.
function detectOS(){
  const ua = navigator.userAgent || '';
  const platform = navigator.platform || '';
  if (/Mac|iPhone|iPad|iPod/.test(platform) || /Mac OS X/.test(ua)) return 'macOS';
  if (/Win/.test(platform) || /Windows/.test(ua)) return 'Windows';
  if (/Linux/.test(platform) || /Linux/.test(ua)) return 'Linux';
  return null;
}

(function osAwareCTA(){
  const os = detectOS();
  if (!os) return;

  const heroBtn = document.querySelector('[data-os-download]');
  if (heroBtn) heroBtn.textContent = `Download for ${os}`;

  document.querySelectorAll('[data-os-card]').forEach(card => {
    if (card.getAttribute('data-os-card') === os) {
      card.classList.add('recommended');
      const badge = document.createElement('span');
      badge.className = 'os-badge';
      badge.textContent = 'Recommended for you';
      card.prepend(badge);
    }
  });
})();

// ---- live GitHub stars ------------------------------------------------------
(function liveStars(){
  const el = document.querySelector('[data-stat="stars"]');
  if (!el) return;
  fetch('https://api.github.com/repos/Sarthak-47/ARGUS')
    .then(r => r.ok ? r.json() : Promise.reject())
    .then(data => {
      if (typeof data.stargazers_count === 'number') {
        el.textContent = data.stargazers_count.toLocaleString();
      }
    })
    .catch(() => { el.closest('.stat')?.remove(); });
})();

// ---- the attack swarm grid (home page only) --------------------------------
(function swarmGrid(){
  const grid = document.getElementById('swarm-grid');
  if (!grid) return;

  const AGENTS = [
    ["ReconBot","Maps the attack surface — links, forms, headers — before anything else runs."],
    ["CrawlerBot","Wordlist-based discovery for backup files, admin panels, and forgotten endpoints."],
    ["Injector","SQL, NoSQL, and command injection — error-based, boolean-blind, and time-based."],
    ["AuthBreaker","JWT forgery, weak secrets, broken session and MFA logic."],
    ["IDORHunter","Insecure direct object references — reading what isn't yours."],
    ["AuthzTester","Broken object/function-level authorization — BOLA/BFLA across two identities."],
    ["XSSHunter","Reflected, stored, and DOM-based cross-site scripting."],
    ["SSRFProber","Server-side request forgery, including blind confirmation via callback."],
    ["HeaderPoker","CORS misconfiguration and access-control bypass headers."],
    ["CSRFHunter","Missing tokens, clickjacking, forced state change."],
    ["FileAttacker","Upload abuse and path traversal — arbitrary file read/write."],
    ["DataExposure","Excessive data exposure — secrets and PII leaking through API responses."],
    ["Fuzzer","Parameter fuzzing across every discovered endpoint."],
    ["RaceCondition","Concurrency bugs — double-spends, missing locks."],
    ["GraphQLAgent","Introspection abuse, batching attacks, depth-limit bypass."],
    ["WebSocketAgent","Origin validation and message-injection over WebSockets."],
    ["MCPSecurityAgent","Tool poisoning and dangerous capabilities in exposed MCP servers."],
    ["PromptInjectionAgent","Fires a canary token at your app's AI features to prove injection."],
    ["BusinessLogicAgent","LLM-reasoned abuse of app-specific workflow rules."],
  ];

  AGENTS.forEach(([name, desc]) => {
    const card = document.createElement('div');
    card.className = 'agent';
    card.setAttribute('tabindex', '0');
    card.innerHTML = `
      <div class="face">
        <svg viewBox="0 0 24 15" width="26" height="16" aria-hidden="true">
          <g fill="none" stroke="#c56a33" stroke-width="1.6">
            <path d="M2 7.5 Q12 1 22 7.5 Q12 14 2 7.5 Z" />
            <circle cx="12" cy="7.5" r="2.6" fill="#7d4f28" stroke="none" />
          </g>
        </svg>
        <div class="name">${name}</div>
      </div>
      <div class="desc">${desc}</div>
    `;
    grid.appendChild(card);
  });
})();
