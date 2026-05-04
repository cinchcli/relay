# Cinch Revenue Model

> Market research snapshot — May 2026. Revisit before public launch.

## Competitor Benchmarks

| Product | Category | Free Tier | Paid Entry | Team/Org | Notes |
|---|---|---|---|---|---|
| **Raycast** | Dev launcher + clipboard | 3-month clip history | $10/mo | $15/user/mo | Unlimited history = upgrade lever |
| **Paste app** | Clipboard manager | 14-day trial | $2.49/mo ($29.99/yr) | $3.49/user/mo | Lowest per-seat in class |
| **ngrok** | Dev tunneling (open-source relay) | 3 endpoints | $8/mo Hobbyist | Custom Enterprise | Closest structural match: AGPL relay + hosted tier |
| **Pushbullet** | Cross-device sync | 25 MB files, 2 GB storage | $3.33/mo (annual) | — | Legacy; declining |
| **Alfred** | Mac productivity + clipboard | Free (core) | £34 one-time | — | One-time; no server costs |
| **Plausible** | AGPL open-core analytics | 30-day trial | $9/mo Starter | $19/mo Business | Reference for AGPL → hosted conversion |
| **Umami** | Open-core analytics | 100k events, 3 sites, 6-mo retention | $20/mo | Same plans | No separate team tier |
| **Resend** | Dev email API | 3k emails/mo | $20/mo Pro | Custom Enterprise | Clean freemium reference for dev APIs |
| **Outline** | Open-core team wiki | 30-day trial | $10/mo (1–10 members) | $79/mo (11–100) | Flat tiers by seat band |
| **Tuple** | Remote pair programming | 14-day trial | $30/user/mo | Custom Enterprise | High WTP: replaces meetings |
| **Sentry** | Error monitoring open-core | 5k errors, 1 user | $26/mo Team | $80/mo Business | Generous free, usage-gated |

---

## Pricing Patterns (Developer Tools)

- **Individual paid sweet spot:** $8–$15/mo. Below $8 = utility; above $15 needs a team story.
- **Team per-seat range:** $6–$30/user/mo. Low end = commodity clipboard (Paste). High end = meeting replacement (Tuple).
- **Annual discount:** 2 months free (16.7%) is the standard framing.
- **Common conversion gates:** retention depth, seat count, binary/media storage, SSO, audit log.

---

## Freemium Limit Recommendations

| Dimension | Free | Rationale |
|---|---|---|
| **Devices** | 3 | Covers laptop + server + VM. Forces upgrade when a teammate joins. Matches ngrok free (3 endpoints). |
| **Clip retention** | 7 days | Clip history is Cinch's core value — intentionally tight to create real pressure. "I need that URL from last week." |
| **Clip count** | 500 | Whichever limit hits first (7 days or 500 clips). |
| **Media storage** | 5 MB total | Text is free; binary is expensive. 5 MB covers the occasional screenshot. |
| **API rate limit** | 100 req/day | Blocks CI abuse without hurting humans. |

---

## Recommended Tier Structure

| Tier | Price | Devices | Retention | Media | Extras |
|---|---|---|---|---|---|
| **Free** | $0 | 3 | 7 days | — (text only) | — |
| **Pro** | $9/mo · $79/yr | 10 | 90 days | 1 GB | Binary clips, full desktop app |
| **Team** | $8/user/mo (annual) · $10/user/mo (monthly) | Unlimited (org) | 1 year | 10 GB pooled | Org management, audit log |
| **Enterprise** | Contact | Unlimited | Custom | Custom | SSO/SAML, SLA, self-hosted support contract |

Annual Pro = $6.58/mo effective. Team annual = $8/user/mo.

---

## Open Core Conversion Benchmarks

- Industry-reported self-host → paid cloud conversion: **2–5%** of self-hosting installs.
- Top conversion drivers (in order):
  1. **Zero ops** — no Docker maintenance, no upgrades, no backup scripts.
  2. **Reliability SLA** — relay downtime = developers cannot paste; pain is immediate.
  3. **Team features** — org management, shared history, audit trail.
  4. **Support SLA** — response time guarantee beyond GitHub issues.
  5. **SSO** — enterprise procurement gate.
- What does NOT convert: feature locks that feel punitive, opaque pricing.

---

## Positioning

**Do not** compete with Raycast or Alfred on "clipboard manager." Their free tiers cover that use case.

**Lead with the remote-push story:** SSH box → Docker container → CI job → Mac clipboard, instantly. This is the gap no clipboard manager fills, and it justifies a separate paid product.

Key differentiators vs. free alternatives (OSC52, iTerm2 built-in):
- Works in non-TTY contexts (CI, cron, Docker exec)
- Persistent history with full-text search
- Bidirectional sync
- Binary / file clip support
- macOS desktop app as a permanent clipboard inbox

---

## Key Risks

| Risk | Mitigation |
|---|---|
| Self-hosting is too easy (5-min Docker Compose) | Aggressive in-product upgrade CTAs: "Clip expires in 2 days. Upgrade to Pro." |
| B2C devs are frugal; churn if no early "wow moment" | 14-day Pro trial, no credit card. Prioritize time-to-first-remote-push. |
| Raycast/Alfred commodity pressure | Keep positioning on SSH/CI/Docker, not clipboard management. |
| Team plan stalls if teammates are Linux-only (no desktop app) | Ensure CLI value is self-sufficient; upsell on retention + audit instead of desktop. |
| OSC52 terminal passthrough is free and already installed | Emphasize non-TTY + history + binary — OSC52 has none of these. |

---

## Potential Add-On

**Self-Host Support** — $49/mo flat: email SLA, priority GitHub issues, migration assistance. Targets compliance-restricted orgs that cannot use cloud but want reliability guarantees.
