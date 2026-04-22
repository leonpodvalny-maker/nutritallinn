# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Live Site

https://nutritallinn.onrender.com (hosted on Render, free tier — cold start ~30 sec after inactivity)

## Project Overview

A minimal Node.js/Express server for a nutrition consultant booking and payment site. Single-file backend (`server.js`) serving static HTML pages with Maksekeskus (Estonian payment processor) integration and Resend email notifications.

## Commands

```bash
# Install dependencies
npm install

# Development (auto-restart on file change)
npm run dev

# Production
npm start
```

No test suite or linter configured.

## Architecture

All backend logic lives in `server.js`. There are no subdirectories.

**Request flow:**
1. User fills order form on `order.html` → `POST /api/checkout`
2. Server validates input, creates a Maksekeskus transaction via REST API, stores order in `pendingOrders` (in-memory), redirects user to payment URL
3. After payment, Maksekeskus calls `POST /api/payment-notify` (server-to-server) with MAC-signed payload
4. Server verifies MAC, looks up the pending order, sends confirmation email via Resend, clears the order from memory
5. Browser is redirected to `/payment-return` → `/success`

**Demo mode:** When `MAKSEKESKUS_SHOP_ID` / `MAKSEKESKUS_SECRET_KEY` are not set, checkout bypasses payment and redirects straight to `/success?demo=1` with order params in the query string.

## Key Details

- **MAC verification** (`verifyMac`): Maksekeskus uses SHA-512 (not HMAC) — sorted JSON keys + secret key, timing-safe comparison. Do not change this algorithm.
- **Valid plans:** Only `'50'` (consultation) and `'175'` (monthly) — enforced via `VALID_PLANS` Set.
- **`pendingOrders`:** In-memory map keyed by `orderId`. Lost on server restart; payment notification falls back to data from the Maksekeskus payload if the order is missing.
- **Static files:** Served from project root (no `public/` subdirectory despite `express.static('public')` — HTML files are served individually via explicit routes).

## Environment Variables

See `.env.example`. Required for live payments:

| Variable | Purpose |
|----------|---------|
| `RESEND_API_KEY` | Resend email API key |
| `MAKSEKESKUS_SHOP_ID` | Maksekeskus shop ID |
| `MAKSEKESKUS_SECRET_KEY` | Maksekeskus secret for MAC signing |
| `SITE_URL` | Public URL for payment redirects (e.g. `https://nutritallinn.onrender.com`) |
| `RECIPIENT_EMAIL` | Email address that receives booking notifications (required, server exits if missing) |
| `RESEND_FROM` | Sender address for emails, e.g. `Нутрициолог <noreply@domain.com>` (optional, defaults to `onboarding@resend.dev`) |
