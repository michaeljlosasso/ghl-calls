/**
 * ghl-calls — LL.Media inbound call log widget.
 *
 * Static assets are served from Workers Assets; /api/* is handled here.
 * Note: rows whose from_number is not a phone number are web-chat sessions
 * ("Guest Visitor 002" -> "Rep Digi") that GHL files under TYPE_CALL. They are
 * excluded -- they are not calls and they skew answer/no-talk rates.
 * The Worker signs a Google service-account JWT with Web Crypto, exchanges it
 * for an access token, and queries BigQuery directly. Results are cached at the
 * edge for CACHE_SECONDS so the nightly sync shows up without a redeploy and
 * without hammering BigQuery on every page load.
 *
 * Secret required:  GCP_SA_KEY  — the full service-account JSON, as a string.
 *   wrangler secret put GCP_SA_KEY
 *
 * A cron trigger also keeps caller names current. ghl.calls is synced once a
 * day around 07:17 ET, so names can never be fresher than that; this runs just
 * behind it, resolves any contact_id it has not seen before against the GHL
 * contacts API, and writes the result to ghl.contacts.
 *
 * The same cron refreshes each caller's GHL "Disposition" custom field into
 * ghl.contact_dispositions (append-only, newest row wins): every inbound caller
 * from the last DISPO_REFRESH_DAYS days, plus any caller never looked up.
 * Dispositions keep changing after the call, so unlike names they are re-read.
 *
 * Secrets for that path:
 *   GCP_SA_KEY_WRITE    — service account allowed to insert into ghl.contacts
 *   CONTACTS_SYNC_KEY   — shared secret for the manual POST /api/sync-contacts
 */

const PROJECT = "ll-media-project";
const CACHE_SECONDS = 3600;
// Bump whenever the /api/data shape changes. The edge cache is per-colo, so
// without this a colo that cached the old shape keeps serving it for up to an
// hour -- new HTML against an old payload, which is how the Name column ended
// up empty for everyone whose nearest colo was already warm.
const PAYLOAD_VERSION = 3;
const TOKEN_SCOPE = "https://www.googleapis.com/auth/bigquery.readonly";
const TOKEN_SCOPE_WRITE = "https://www.googleapis.com/auth/bigquery";
const SYNC_MAX_CONTACTS = 300;   // per run; ~40 new contacts/day, so ample
const SYNC_CONCURRENCY = 6;
const SYNC_LOOKBACK_DAYS = 14;   // resilience if the cron misses a few nights
// Dispositions: ~240 inbound callers per 30 days. Each run costs one GHL call
// per contact plus one per sub-account (to find its Disposition field id), so
// the cap keeps a run well inside the Worker's subrequest limit.
const DISPO_REFRESH_DAYS = 30;
const DISPO_MAX_CONTACTS = 450;

/* ------------------------------------------------------------------ auth */

function b64url(buf) {
  const bytes = buf instanceof ArrayBuffer ? new Uint8Array(buf) : buf;
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function pemToPkcs8(pem) {
  const body = pem
    .replace(/-----BEGIN PRIVATE KEY-----/, "")
    .replace(/-----END PRIVATE KEY-----/, "")
    .replace(/\s+/g, "");
  const raw = atob(body);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out.buffer;
}

const tokenCache = {}; // keyed by secret+scope — reused on a warm isolate

async function getAccessToken(env, keyName = "GCP_SA_KEY", scope = TOKEN_SCOPE) {
  const now = Math.floor(Date.now() / 1000);
  const ck = keyName + "|" + scope;
  const hit = tokenCache[ck];
  if (hit && hit.exp > now + 60) return hit.token;

  if (!env[keyName]) throw new Error(keyName + " secret is not set");
  const sa = JSON.parse(env[keyName]);

  const header = { alg: "RS256", typ: "JWT" };
  const claim = {
    iss: sa.client_email,
    scope,
    aud: "https://oauth2.googleapis.com/token",
    exp: now + 3600,
    iat: now,
  };
  const unsigned = `${b64url(new TextEncoder().encode(JSON.stringify(header)))}.${b64url(
    new TextEncoder().encode(JSON.stringify(claim))
  )}`;

  const key = await crypto.subtle.importKey(
    "pkcs8",
    pemToPkcs8(sa.private_key),
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    key,
    new TextEncoder().encode(unsigned)
  );
  const jwt = `${unsigned}.${b64url(sig)}`;

  const resp = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion: jwt,
    }),
  });
  if (!resp.ok) throw new Error(`token exchange failed: ${resp.status} ${await resp.text()}`);
  const data = await resp.json();
  tokenCache[ck] = { token: data.access_token, exp: now + (data.expires_in || 3600) };
  return tokenCache[ck].token;
}

/* -------------------------------------------------------------- bigquery */

async function bq(env, sql, keyName, scope) {
  const token = await getAccessToken(env, keyName, scope);
  const resp = await fetch(
    `https://bigquery.googleapis.com/bigquery/v2/projects/${PROJECT}/queries`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        query: sql,
        useLegacySql: false,
        location: "US",
        timeoutMs: 60000,
        maxResults: 100000,
      }),
    }
  );
  const data = await resp.json();
  if (!resp.ok) {
    throw new Error(`bigquery: ${resp.status} ${JSON.stringify(data.error || data)}`);
  }
  if (data.jobComplete === false) throw new Error("bigquery: query timed out");
  const fields = (data.schema?.fields || []).map((f) => f.name);
  const rows = (data.rows || []).map((r) => r.f.map((c) => c.v));
  return { fields, rows };
}

/* ------------------------------------------------------------------ data */

const SQL_CALLS = `
  SELECT
    message_id,
    location_id,
    FORMAT_DATE('%Y-%m-%d', call_date_et)        AS d,
    FORMAT_DATETIME('%H:%M:%S', call_timestamp_et) AS t,
    status,
    from_number,
    to_number,
    duration_seconds,
    contact_id
  FROM \`${PROJECT}.ghl.calls\`
  WHERE direction = 'inbound'
    AND REGEXP_CONTAINS(from_number, r'^\\+?[0-9]')
  ORDER BY call_timestamp_et
`;

// Display names come from ghl.locations (re-synced daily), NOT from the name
// frozen onto each call row at pull time. GHL sub-accounts get renamed and
// recycled -- "OPEN - Pella Nashville" is GES Bath today -- and a renamed
// account carries both names in ghl.calls, so ANY_VALUE() there returned a
// stale, nondeterministic label. Falls back to the call-row name if a location
// is somehow absent from the locations table.
const SQL_LOCATIONS = `
  WITH called AS (
    SELECT location_id, ANY_VALUE(location_name) AS fallback_name
    FROM \`${PROJECT}.ghl.calls\`
    WHERE direction = 'inbound'
      AND REGEXP_CONTAINS(from_number, r'^\\+?[0-9]')
    GROUP BY location_id
  )
  SELECT c.location_id,
         TRIM(COALESCE(l.location_name, c.fallback_name)) AS location_name
  FROM called c
  LEFT JOIN \`${PROJECT}.ghl.locations\` l USING(location_id)
  ORDER BY location_name
`;

const SQL_META = `
  SELECT
    FORMAT_TIMESTAMP('%Y-%m-%dT%H:%M:%SZ', MAX(pulled_at))      AS last_sync,
    FORMAT_DATE('%Y-%m-%d', MIN(call_date_et))                  AS first_date,
    FORMAT_DATE('%Y-%m-%d', MAX(call_date_et))                  AS last_date,
    CAST(COUNT(*) AS STRING)                                    AS all_rows
  FROM \`${PROJECT}.ghl.calls\`
`;

// Caller names, where we have them. GHL purges old contacts per sub-account,
// so this table is deliberately sparse -- absent means "we don't know", and
// the widget just leaves the cell blank.
const SQL_CONTACTS = `
  SELECT contact_id,
         COALESCE(first_name,'') AS first_name,
         COALESCE(last_name,'')  AS last_name
  FROM \`${PROJECT}.ghl.contacts\`
  WHERE status = 'ok' AND (first_name IS NOT NULL OR last_name IS NOT NULL)
`;

// Current Disposition per caller. Blank, purged and no-field contacts are
// left out, so absent means "no disposition" and the cell shows a dash.
const SQL_DISPOSITIONS = `
  SELECT contact_id, ANY_VALUE(disposition) AS disposition
  FROM \`${PROJECT}.ghl.vw_contact_dispositions_latest\`
  WHERE status = 'ok' AND disposition IS NOT NULL AND disposition != ''
  GROUP BY contact_id
`;

async function buildPayload(env) {
  const [calls, locations, meta, contacts, dispos] = await Promise.all([
    bq(env, SQL_CALLS),
    bq(env, SQL_LOCATIONS),
    bq(env, SQL_META),
    bq(env, SQL_CONTACTS),
    bq(env, SQL_DISPOSITIONS),
  ]);

  const locMap = {};
  for (const [id, name] of locations.rows) locMap[id] = name;

  const m = meta.rows[0] || [];
  return {
    generated_at: new Date().toISOString(),
    payload_version: PAYLOAD_VERSION,
    timezone: "America/New_York",
    meta: {
      last_sync: m[0] || null,
      first_date: m[1] || null,
      last_date: m[2] || null,
      all_rows: Number(m[3] || 0),
    },
    locations: locMap,
    // { contact_id: [first, last] } -- only contacts we actually resolved
    contacts: Object.fromEntries(contacts.rows.map((r) => [r[0], [r[1] || "", r[2] || ""]])),
    // { contact_id: "Appointment Booked" } -- only contacts with a value
    dispositions: Object.fromEntries(dispos.rows.map((r) => [r[0], r[1]])),
    fields: ["id", "loc", "date", "time", "status", "from", "to", "dur", "cid"],
    // [message_id, location_id, YYYY-MM-DD, HH:MM:SS, status, from, to, seconds, contact_id]
    rows: calls.rows.map((r) => [
      r[0], r[1], r[2], r[3], r[4], r[5], r[6],
      r[7] === null || r[7] === undefined ? null : Number(r[7]),
      r[8] || null,
    ]),
  };
}

/* -------------------------------------------------------- contact names */

// Contacts we have never looked up. Restricted to recent calls: ghl.calls is
// partitioned on call_date_et, and old contacts are mostly purged by GHL
// anyway, so scanning all of history would cost more and return less.
const SQL_PENDING_CONTACTS = `
  SELECT c.location_id, c.contact_id, ANY_VALUE(t.pit_token) AS pit_token
  FROM \`${PROJECT}.ghl.calls\` c
  JOIN \`${PROJECT}.ghl.location_tokens\` t USING (location_id)
  LEFT JOIN \`${PROJECT}.ghl.contacts\` k
         ON k.contact_id = c.contact_id AND k.location_id = c.location_id
  WHERE c.direction = 'inbound'
    AND c.contact_id IS NOT NULL
    AND k.contact_id IS NULL
    AND REGEXP_CONTAINS(c.from_number, r'^\\+?[0-9]')
    AND c.call_date_et >= DATE_SUB(CURRENT_DATE('America/New_York'), INTERVAL ${SYNC_LOOKBACK_DAYS} DAY)
  GROUP BY c.location_id, c.contact_id
  LIMIT ${SYNC_MAX_CONTACTS}
`;

// 200 = found. 400 "Contact not found" = GHL has purged it, record that so we
// stop asking. Anything else (401, 429, 5xx) is transient: leave the contact
// unrecorded so the next run retries it.
async function fetchContactName(contactId, pit) {
  const resp = await fetch(`https://services.leadconnectorhq.com/contacts/${contactId}`, {
    headers: { Authorization: `Bearer ${pit}`, Version: "2021-07-28", Accept: "application/json" },
  });
  if (resp.status === 200) {
    const j = await resp.json();
    const c = j.contact || j;
    return { status: "ok", first: (c.firstName || "").trim(), last: (c.lastName || "").trim() };
  }
  if (resp.status === 400) {
    const body = await resp.text();
    if (body.includes("not found")) return { status: "missing", first: "", last: "" };
  }
  return null; // transient — retry next run
}

async function mapPool(items, limit, fn) {
  const out = new Array(items.length);
  let i = 0;
  await Promise.all(
    Array.from({ length: Math.min(limit, items.length) }, async () => {
      while (i < items.length) {
        const k = i++;
        try { out[k] = await fn(items[k]); } catch { out[k] = null; }
      }
    })
  );
  return out;
}

async function syncContactNames(env) {
  const pending = await bq(env, SQL_PENDING_CONTACTS);
  if (!pending.rows.length) return { pending: 0, named: 0, missing: 0, skipped: 0, inserted: 0 };

  const results = await mapPool(pending.rows, SYNC_CONCURRENCY, async ([locationId, contactId, pit]) => {
    if (!pit) return null;
    const r = await fetchContactName(contactId, pit);
    return r && { locationId, contactId, ...r };
  });

  const got = results.filter(Boolean);
  if (!got.length) {
    return { pending: pending.rows.length, named: 0, missing: 0, skipped: pending.rows.length, inserted: 0 };
  }

  // Streaming insert: no SQL string building, and insertId makes a retried
  // run idempotent rather than duplicating rows.
  const now = new Date().toISOString();
  const body = {
    skipInvalidRows: false,
    rows: got.map((g) => ({
      insertId: `${g.locationId}:${g.contactId}`,
      json: {
        location_id: g.locationId,
        contact_id: g.contactId,
        first_name: g.first || null,
        last_name: g.last || null,
        status: g.status,
        source: "ghl_api",
        synced_at: now,
      },
    })),
  };
  const token = await getAccessToken(env, "GCP_SA_KEY_WRITE", TOKEN_SCOPE_WRITE);
  const resp = await fetch(
    `https://bigquery.googleapis.com/bigquery/v2/projects/${PROJECT}/datasets/ghl/tables/contacts/insertAll`,
    { method: "POST", headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify(body) }
  );
  const out = await resp.json();
  if (!resp.ok || out.insertErrors) {
    throw new Error(`contacts insert failed: ${resp.status} ${JSON.stringify(out).slice(0, 400)}`);
  }

  return {
    pending: pending.rows.length,
    named: got.filter((g) => g.status === "ok" && (g.first || g.last)).length,
    missing: got.filter((g) => g.status === "missing").length,
    skipped: pending.rows.length - got.length,
    inserted: got.length,
  };
}

/* --------------------------------------------------------- dispositions */

// Callers due a (re)read: anyone never read, then recent callers whose last
// read is older than ~a day. Purged contacts are never re-asked.
const SQL_PENDING_DISPOSITIONS = `
  WITH callers AS (
    SELECT location_id, contact_id, MAX(call_date_et) AS last_call
    FROM \`${PROJECT}.ghl.calls\`
    WHERE direction = 'inbound' AND contact_id IS NOT NULL
      AND REGEXP_CONTAINS(from_number, r'^\\+?[0-9]')
    GROUP BY location_id, contact_id
  )
  SELECT c.location_id, c.contact_id, t.pit_token
  FROM callers c
  JOIN (SELECT location_id, pit_token FROM \`${PROJECT}.ghl.location_tokens\`
        WHERE pit_token IS NOT NULL
        QUALIFY ROW_NUMBER() OVER (PARTITION BY location_id ORDER BY created_at DESC) = 1) t
    USING (location_id)
  LEFT JOIN \`${PROJECT}.ghl.vw_contact_dispositions_latest\` d USING (location_id, contact_id)
  WHERE d.contact_id IS NULL
     OR (d.status != 'missing'
         AND c.last_call >= DATE_SUB(CURRENT_DATE('America/New_York'), INTERVAL ${DISPO_REFRESH_DAYS} DAY)
         AND d.synced_at < TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 20 HOUR))
  ORDER BY d.contact_id IS NULL DESC, c.last_call DESC
  LIMIT ${DISPO_MAX_CONTACTS}
`;

const GHL_HEADERS = (pit) => ({ Authorization: `Bearer ${pit}`, Version: "2021-07-28", Accept: "application/json" });

// The Disposition field has a different id in every sub-account. Returns the
// id, null when the sub-account has no such field, or undefined on an error.
async function dispositionFieldId(locationId, pit) {
  const resp = await fetch(`https://services.leadconnectorhq.com/locations/${locationId}/customFields`,
    { headers: GHL_HEADERS(pit) });
  if (!resp.ok) return undefined;
  const fields = (await resp.json()).customFields || [];
  const name = (f) => String(f.name || "").trim().toLowerCase();
  const f = fields.find((x) => name(x) === "disposition") || fields.find((x) => name(x).includes("disposition"));
  return f ? f.id : null;
}

// Same 200 / 400-not-found / transient contract as fetchContactName.
async function fetchDisposition(contactId, pit, fieldId) {
  const resp = await fetch(`https://services.leadconnectorhq.com/contacts/${contactId}`, { headers: GHL_HEADERS(pit) });
  if (resp.status === 200) {
    const c = (await resp.json()).contact || {};
    let v = ((c.customFields || []).find((x) => x.id === fieldId) || {}).value;
    if (Array.isArray(v)) v = v.join(", ");
    v = v == null ? "" : String(v).trim();
    return { status: "ok", disposition: v || null };
  }
  if (resp.status === 400 || resp.status === 404) {
    if ((await resp.text()).toLowerCase().includes("not found")) return { status: "missing", disposition: null };
  }
  return null;
}

async function syncDispositions(env) {
  const pending = await bq(env, SQL_PENDING_DISPOSITIONS);
  if (!pending.rows.length) return { pending: 0, inserted: 0 };

  const tokens = {};
  for (const [loc, , pit] of pending.rows) tokens[loc] = pit;
  const fieldIds = {};
  await mapPool(Object.keys(tokens), SYNC_CONCURRENCY, async (loc) => {
    fieldIds[loc] = await dispositionFieldId(loc, tokens[loc]);
  });

  const results = await mapPool(pending.rows, SYNC_CONCURRENCY, async ([locationId, contactId, pit]) => {
    const fid = fieldIds[locationId];
    if (fid === undefined) return null;                       // field lookup failed: retry next run
    if (fid === null) return { locationId, contactId, status: "no_field", disposition: null };
    const r = await fetchDisposition(contactId, pit, fid);
    return r && { locationId, contactId, ...r };
  });
  const got = results.filter(Boolean);
  if (!got.length) return { pending: pending.rows.length, inserted: 0 };

  // Append-only by design (a new snapshot each read), so no insertId dedupe.
  const now = new Date().toISOString();
  const token = await getAccessToken(env, "GCP_SA_KEY_WRITE", TOKEN_SCOPE_WRITE);
  const resp = await fetch(
    `https://bigquery.googleapis.com/bigquery/v2/projects/${PROJECT}/datasets/ghl/tables/contact_dispositions/insertAll`,
    { method: "POST", headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ skipInvalidRows: false, rows: got.map((g) => ({ json: {
        location_id: g.locationId, contact_id: g.contactId, disposition: g.disposition,
        status: g.status, synced_at: now } })) }) }
  );
  const out = await resp.json();
  if (!resp.ok || out.insertErrors) {
    throw new Error(`dispositions insert failed: ${resp.status} ${JSON.stringify(out).slice(0, 400)}`);
  }
  return {
    pending: pending.rows.length,
    inserted: got.length,
    with_value: got.filter((g) => g.disposition).length,
    missing: got.filter((g) => g.status === "missing").length,
    skipped: pending.rows.length - got.length,
  };
}

/* --------------------------------------------------------------- handler */

const JSON_HEADERS = {
  "Content-Type": "application/json; charset=utf-8",
  // The widget is embedded cross-origin in the dashboard iframe.
  "Access-Control-Allow-Origin": "*",
};

export default {
  // Runs just after the nightly ghl.calls sync so new calls arrive with their
  // caller name already resolved.
  async scheduled(event, env, ctx) {
    ctx.waitUntil((async () => {
      await syncContactNames(env)
        .then((s) => console.log("contact-name sync", JSON.stringify(s)))
        .catch((e) => console.error("contact-name sync failed:", e && e.message ? e.message : e));
      await syncDispositions(env)
        .then((s) => console.log("disposition sync", JSON.stringify(s)))
        .catch((e) => console.error("disposition sync failed:", e && e.message ? e.message : e));
    })());
  },

  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (!url.pathname.startsWith("/api/")) {
      return env.ASSETS.fetch(request);
    }

    if (url.pathname === "/api/health") {
      return new Response(JSON.stringify({ ok: true, ts: new Date().toISOString() }), {
        headers: JSON_HEADERS,
      });
    }

    // Manual "run it now" for the name sync. Guarded by a shared secret; the
    // widget never calls this.
    if (url.pathname === "/api/sync-contacts") {
      const key = request.headers.get("X-Sync-Key") || url.searchParams.get("key");
      if (!env.CONTACTS_SYNC_KEY || key !== env.CONTACTS_SYNC_KEY) {
        return new Response(JSON.stringify({ error: "unauthorized" }), { status: 401, headers: JSON_HEADERS });
      }
      try {
        const names = await syncContactNames(env);
        const dispositions = await syncDispositions(env);
        return new Response(JSON.stringify({ ok: true, names, dispositions }), { headers: JSON_HEADERS });
      } catch (err) {
        return new Response(JSON.stringify({ error: String(err && err.message ? err.message : err) }),
          { status: 500, headers: JSON_HEADERS });
      }
    }

    if (url.pathname === "/api/data") {
      const bust = url.searchParams.get("refresh") === "1";
      const cache = caches.default;
      const cacheKey = new Request(
        new URL(`/api/data?v=${PAYLOAD_VERSION}`, url.origin).toString(),
        { method: "GET" }
      );

      if (!bust) {
        const hit = await cache.match(cacheKey);
        if (hit) {
          const r = new Response(hit.body, hit);
          r.headers.set("X-Cache", "HIT");
          // Edge keeps the 1h copy; browsers must always revalidate so
          // deploys and nightly syncs show up on a plain refresh.
          r.headers.set("Cache-Control", "no-store");
          return r;
        }
      }

      try {
        const payload = await buildPayload(env);
        const body = JSON.stringify(payload);
        // Edge copy carries max-age so caches.default honors the 1h TTL...
        const edgeCopy = new Response(body, {
          headers: {
            ...JSON_HEADERS,
            "Cache-Control": `public, max-age=${CACHE_SECONDS}`,
          },
        });
        ctx.waitUntil(cache.put(cacheKey, edgeCopy));
        // ...but the client response is never browser-cached.
        return new Response(body, {
          headers: { ...JSON_HEADERS, "Cache-Control": "no-store", "X-Cache": "MISS" },
        });
      } catch (err) {
        return new Response(
          JSON.stringify({ error: String(err && err.message ? err.message : err) }),
          { status: 500, headers: JSON_HEADERS }
        );
      }
    }

    return new Response(JSON.stringify({ error: "not found" }), {
      status: 404,
      headers: JSON_HEADERS,
    });
  },
};
