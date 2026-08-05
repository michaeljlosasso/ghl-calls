# ghl-calls

LL.Media inbound call log widget. Content-only — no header, logo, footer, nav, or
auth — so it embeds directly into the main dashboard iframe.

**Live:** https://ghl-calls.michael-5fa.workers.dev

## Architecture

Cloudflare Worker with Workers Assets (SPA fallback). `/api/*` is handled by the
Worker; everything else serves the static widget.

`/api/data` signs a Google service-account JWT with Web Crypto, exchanges it for
an access token, and queries `ll-media-project.ghl.calls` directly. The response
is cached at the edge for 1 hour, so the nightly 7:15am ET sync appears without a
redeploy. Add `?refresh=1` to bypass the cache.

## Deploy

```bash
export CLOUDFLARE_API_TOKEN=...
export CLOUDFLARE_ACCOUNT_ID=5fae18315616c9ecfd8f06baa13d3e10
wrangler secret put GCP_SA_KEY < claude_gcp.json   # first time only
wrangler deploy
```

`GCP_SA_KEY` is the full service-account JSON as a string. It needs
`bigquery.readonly` plus job-create on `ll-media-project`.

## Design

Follows `LL.Media Widget Design Specification` (2026-07-27), which supersedes the
older `ll-media-sub-widget` skill wherever they disagree — 14px card radius, 38px
icon badges, tinted borderless status chips, teal-gradient calendar selection.

Chart palette validated for colorblind separation before shipping.

## Data notes

- All timestamps are Eastern. `duration_seconds` is null for no-answer/voicemail.
- "Today" anchors to the newest date in the data, not the wall clock — the sync
  runs at 07:15 ET, so the real current day is often legitimately empty.
- Default preset is Month To Date, per the design spec.
