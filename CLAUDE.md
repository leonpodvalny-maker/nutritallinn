# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Where the site lives

| Part | URL | Served by |
|------|-----|-----------|
| Pages | https://nutritallinn.fitfoodestonia.ee | cPanel (Virtuaal), static files |
| API | https://site.nutritallinn.workers.dev | the Worker, `src/index.js` |

The pages are plain HTML on a PHP host that cannot run the API, so their forms
post across to the Worker, which redirects the visitor back. Render is gone;
so is `server.js`.

**A copy of the pages lives on cPanel and is not in this repo.** It is `public/`
with two changes: form `action`s rewritten to absolute Worker URLs, and an
`.htaccess` doing extensionless rewrites plus an HTTPS redirect. Edit `public/`,
run `npm run build:cpanel`, upload the zip it writes — or the two drift apart.

## Project overview

A booking and payment site for a nutrition consultant. Static HTML pages plus
three API routes: Maksekeskus for payments, Resend for email.

## Commands

```bash
npm run dev                 # local, http://localhost:8787
npm run deploy              # publish the Worker
npm run tail                # live logs
npm run build:cpanel        # build the static copy for the page host
```

No test suite or linter.

## Architecture

`src/index.js` is the whole Worker — routes, validation, MAC verification,
email. It also serves `public/` through the `ASSETS` binding, so the Worker URL
shows the same site as the public one; that copy is what cPanel is built from.

**Payment flow:**
1. `order.html` posts to `/api/checkout`
2. Worker validates, creates a Maksekeskus transaction, stores the order in KV, redirects to the payment page
3. Maksekeskus posts to `/api/payment-notify` with a MAC-signed payload
4. Worker verifies the MAC, sends both emails via Resend, deletes the KV entry
5. Browser lands on `/payment-return` → `/success`

**Survey flow:** `/survey` posts to `/api/survey`, which emails the owner
immediately — no payment involved.

**Demo mode:** without `MAKSEKESKUS_SHOP_ID`/`MAKSEKESKUS_SECRET_KEY`, checkout
sends the mail immediately and redirects to `/success?demo=1`.

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
  `withSecurityHeaders`. The cPanel copy sets its own in `.htaccess`.
- **Two origins, two jobs.** `ALLOWED_ORIGINS` decides where a *visitor* is sent
  back to after posting a form — an unlisted referrer falls back to the first
  entry, so it cannot be used as an open redirect. It does not restrict who may
  POST. `API_ORIGIN` is where Maksekeskus is told to send the payment
  notification and the return leg: **configuration, never a request header** —
  only the Worker can verify a MAC or run `/payment-return`.

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
| `ALLOWED_ORIGINS` | Hosts a visitor may be redirected back to, comma-separated; first entry is the public site |
| `API_ORIGIN` | Where Maksekeskus sends the notification — the Worker |

Resend refuses to send to anyone but the account owner until a domain is
verified. `fitfoodestonia.ee` is verified, so `RESEND_FROM` must stay on that
domain.

The last two are plain vars in `wrangler.toml`, not secrets.

## Known gaps

- **The payment path has never run for real** — this site has had no orders.
  The notification URL in the Maksekeskus dashboard must be
  `https://site.nutritallinn.workers.dev/api/payment-notify`.
- Repeated notifications would send duplicate emails; there is no idempotency
  marker. Judged acceptable at this volume.
- A Resend failure after the notification is acknowledged only reaches the log.
