# AGENTS.md

This file provides guidance to Codex (Codex.ai/code) when working with code in this repository.

## Two deployments, one repo

The same site runs on two hosts while the move off Render finishes:

| Host | URL | Entry point | Deployed by |
|------|-----|-------------|-------------|
| Cloudflare Workers | https://site.nutritallinn.workers.dev | `src/index.js` | `npx wrangler deploy` |
| Render (legacy) | https://nutritallinn.onrender.com | `server.js` | push to `main` |

Workers is the target: it has no cold start, Render's free tier sleeps after
15 minutes and takes ~30 seconds to wake. Render stays up until a real payment
has been put through Workers.

**Editing pages means editing twice.** `public/` holds the copies Workers
serves; the identical files at the repo root are what Render serves. Change one
and the two sites drift apart. Both copies disappear when Render is retired.

## Project overview

A booking and payment site for a nutrition consultant. Static HTML pages plus
three API routes: Maksekeskus for payments, Resend for email.

## Commands

```bash
# Worker (the one that matters)
npx wrangler dev            # local, http://localhost:8787
npx wrangler deploy         # publish
npx wrangler tail           # live logs

# Express (Render only)
npm run dev
npm start
```

No test suite or linter.

## Architecture

`src/index.js` is the whole Worker — routes, validation, MAC verification,
email. Cloudflare serves `public/` through the `ASSETS` binding; the Worker
maps extensionless paths (`/order` → `order.html`) and generates `robots.txt`
and `sitemap.xml` from the request origin, so no host is hardcoded.

**Payment flow:**
1. `order.html` posts to `/api/checkout`
2. Worker validates, creates a Maksekeskus transaction, stores the order in KV, redirects to the payment page
3. Maksekeskus posts to `/api/payment-notify` with a MAC-signed payload
4. Worker verifies the MAC, sends both emails via Resend, deletes the KV entry
5. Browser lands on `/payment-return` → `/success`

**Survey flow:** `/survey` posts to `/api/survey`, which emails the owner
immediately — no payment involved.

**Demo mode:** without `MAKSEKESKUS_SHOP_ID`/`MAKSEKESKUS_SECRET_KEY`, checkout
skips payment and redirects to `/success?demo=1`, which sends the mail itself.

## Key details

- **Plans** live in one `PLANS` map: `100` (consultation), `75` (follow-up),
  `150` (7-day meal plan). Prices come from the server; the client cannot set them.
- **MAC** is plain SHA-512 over the payload plus the secret key, not HMAC.
  Verification accepts two serialisations — a re-serialised sorted object, and
  the raw JSON string exactly as received (what Maksekeskus documents). Both
  require the secret, so accepting either does not weaken authentication.
  **Do not narrow this** until a real callback proves which form arrives.
- **Order ids** are `NTL-` plus 16 hex characters, 20 in total: Maksekeskus
  documents a 20-character limit on the reference.
- **KV** (`ORDERS` binding) holds pending orders for 30 minutes and the rate
  limiter's counters under an `rl:` prefix. It is eventually consistent — if a
  notification arrives before the write lands, the owner still gets a mail
  saying the form data is missing.
- **Rate limit:** 10 posts per IP per 15 minutes on `/api/checkout` and
  `/api/survey`. `/api/payment-notify` is deliberately unlimited — the retries
  are legitimate and already authenticated by the MAC. A KV failure inside the
  limiter fails open rather than failing the request.
- **Security headers** (CSP and friends) wrap every response in one place, in
  `withSecurityHeaders`.

## Configuration

Worker secrets are set with `npx wrangler secret put NAME`.

> On Windows, `Ctrl+V` at wrangler's prompt stores the paste character itself
> as the value. Pipe it instead: `"value" | npx wrangler secret put NAME`.

| Variable | Purpose |
|----------|---------|
| `RESEND_API_KEY` | Resend API key |
| `RECIPIENT_EMAIL` | Where booking notifications go |
| `RESEND_FROM` | Sender, e.g. `Нутрициолог <noreply@fitfoodestonia.ee>` |
| `MAKSEKESKUS_SHOP_ID` | Maksekeskus shop id |
| `MAKSEKESKUS_SECRET_KEY` | Maksekeskus secret, used for MAC signing |
| `SITE_URL` | Optional; the Worker derives its own origin when unset |

Resend refuses to send to anyone but the account owner until a domain is
verified. `fitfoodestonia.ee` is verified, so `RESEND_FROM` must stay on that
domain. Render reads the same names from its own environment settings.

## Known gaps

- **The payment path has never run for real** — this site has had no orders.
  Before testing, point the notification URL in the Maksekeskus dashboard at
  the host being tested.
- Repeated notifications would send duplicate emails; there is no idempotency
  marker. Judged acceptable at this volume.
- A Resend failure after the notification is acknowledged only reaches the log.
