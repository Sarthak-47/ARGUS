# Argus — visual world

> **Pinned reference.** This world is fixed by the user's Claude Design file
> (`Argus.dc.html`, "THE WATCH"). It is the design authority: where this
> document and personal taste disagree, this document wins. Earlier
> explorations — terracotta pottery, Ichor/verdigris, glass islands, the
> dossier — are **anti-reference**. Do not reintroduce them.

## The world

A keeper's watch-ledger. Warm near-black ground, a single old-gold accent, and
type doing the structural work. It reads as something *kept* — a register
written up nightly — not as a dashboard.

## Palette

**Verified against the user's official design handoff** (the
`design_handoff_argus_security_scanner` bundle exported from Claude Design:
`Argus.dc.html`, `Argus.html`, `README.md` — the README states the tokens
explicitly, so this is read, not eyeballed). The ground is cool graphite, not
warm brown.

| Token | Value | Use |
|---|---|---|
| `ground` | `#08080A` | page |
| `ground-raised` | `#131318` | the rare raised plane |
| `gold` | `#C9A227` | the single accent: numerals, active nav, open eyes, and also `HIGH` severity — not a second alarm colour |
| `gold-dim` | `#7A6520` | rules, dormant marks |
| `grave` | `#8E2B20` | `CRITICAL` severity, the one alarm colour |
| `grave-lit` | `#B4392A` | grave's own "alive" pulse tone (alternates with `grave` on wounded/alarmed eyes) — not a brighter red, the reference never uses one |
| `grave-panel` | `#2a1215` | inset panel for a grave callout |
| `bone` | `#EDEAE4` | reading text, and emphasis |
| `bone-dim` | `#8B8996` | labels, secondary — cool grey, not warm |
| `bone-dim-2` | `#55545C` | tertiary, darker |
| `bone-dim-3` | `#6C6A76` | `MEDIUM`/`LOW` severity — bone/dim, not colour |
| `rule` | `#17171C` | subtle hairline |
| `rule-strong` | `#23232A` | solid hairline |
| `rule-dotted` | `#2B2B33` | dotted leader |
| `shut` | `#4A4954` | closed/asleep eye lids, disabled state |

No second accent, no severity rainbow beyond gold → grave: only `CRITICAL` is
oxblood; `HIGH` is gold, `MEDIUM` is bone, `LOW`/`INFO` are dim grey.

## Type

**Verified, not guessed:** the serif is **Bodoni Moda** (a Didone — dramatic
thin/thick stroke contrast), not Cormorant Garamond. The mono is **IBM Plex
Mono**, not JetBrains. Only weights 400 and 500 appear anywhere in the export
— the Didone's own contrast carries visual weight at large sizes, so a bold
cut is never needed, even for the masthead or the big posture numeral.

- **Display / numerals:** Bodoni Moda, wide-tracked caps for the masthead,
  large and unadorned for figures. Weight 400–500 only.
- **Labels & meta:** IBM Plex Mono, uppercase, tracking mostly 0.16–0.24em.
  This is a ledger convention — measurement and record — not a "technical"
  costume.
- **Reading text:** Bodoni Moda, comfortable measure, for the register
  entries and asides.
- One italic Bodoni aside per screen, in the mythic register.
- Controls (rare) use the system sans stack, not a named font.

## Structure

- Masthead: `A R G U S` wide-tracked serif caps, italic serif tagline beside
  it, roman-numeral nav right (`I THE WATCH · II SET THE WATCH · III THE
  REGISTER`), active item underlined in gold.
- A mono-caps meta rule beneath: date · UTC · keeper on the left, live counts
  on the right.
- Three columns on the watch: posture (left), the hundred eyes (centre), the
  register of events (right).
- **Dotted leaders** join a mono-caps label to its serif value. The leader is
  the container; there are no cards.

## Bans (specific to this world)

Flat and matte throughout. No gradients, no glow, no blur, no rounded
translucent panels, no drop shadows, no card grids. Structure comes from
hairline rules, dotted leaders and space.

## The hundred eyes

**Verified against the reference's actual `drawSphere`/`eyeGeom` source**, not
approximated: a canvas field of exactly 100 almond eyes (gold lens, dark
pupil, quadratic-curve lid, thin pale outline), placed by a Fibonacci-sphere
projection and slowly rotated (`rot = t * 0.16`) rather than laid flat. Nearer
eyes (higher local z after rotation) are drawn larger, more opaque, and more
saturated gold; farther ones dim toward `gold-dim`. Pupils offset toward the
cursor; each eye blinks on its own randomized timer. Two thin guide rings
bound the field.

One eye per vulnerability class the engine checks, in order, for the first
`VULN_CHECKS.length` — open and gold when clean, grave and alternating
`grave`/`grave-lit` when that class caught something real. The remaining
eyes, out to the mythical hundred, are unbound ornament (never a fabricated
finding) with a small fixed fraction reading as asleep/drowsy for texture. The
ornament *is* the readout.

## Voice

Mythic and plain at once: *the watch, sweep, keeper, lulled, grave, the ground,
posture of the estate, what the eyes saw*. Never cute, never explanatory.
