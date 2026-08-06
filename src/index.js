/**
 * ghl-calls — LL.Media inbound call log widget.
 *
 * Static assets are served from Workers Assets; /api/* is handled here.
 * The Worker signs a Google service-account JWT with Web Crypto, exchanges it
 * for an access token, and queries BigQuery directly. Results are cached at the
 * edge for CACHE_SECONDS so the nightly sync shows up without a redeploy and
 * without hammering BigQuery on every page load.
 *
 * Secret required:  GCP_SA_KEY  — the full service-account JSON, as a string.
 *   wrangler secret put GCP_SA_KEY
 */

const PROJECT = "ll-media-project";
const CACHE_SECONDS = 3600;
const TOKEN_SCOPE = "https://www.googleapis.com/auth/bigquery.readonly";

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

let cachedToken = null; // { token, exp } — reused across requests on a warm isolate

async function getAccessToken(env) {
  const now = Math.floor(Date.now() / 1000);
  if (cachedToken && cachedToken.exp > now + 60) return cachedToken.token;

  if (!env.GCP_SA_KEY) throw new Error("GCP_SA_KEY secret is not set");
  const sa = JSON.parse(env.GCP_SA_KEY);

  const header = { alg: "RS256", typ: "JWT" };
  const claim = {
    iss: sa.client_email,
    scope: TOKEN_SCOPE,
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
  cachedToken = { token: data.access_token, exp: now + (data.expires_in || 3600) };
  return cachedToken.token;
}

/* -------------------------------------------------------------- bigquery */

async function bq(env, sql) {
  const token = await getAccessToken(env);
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
  ORDER BY call_timestamp_et
`;

const SQL_LOCATIONS = `
  SELECT location_id, ANY_VALUE(location_name) AS location_name
  FROM \`${PROJECT}.ghl.calls\`
  WHERE direction = 'inbound'
  GROUP BY location_id
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

async function buildPayload(env) {
  const [calls, locations, meta] = await Promise.all([
    bq(env, SQL_CALLS),
    bq(env, SQL_LOCATIONS),
    bq(env, SQL_META),
  ]);

  const locMap = {};
  for (const [id, name] of locations.rows) locMap[id] = name;

  const m = meta.rows[0] || [];
  return {
    generated_at: new Date().toISOString(),
    timezone: "America/New_York",
    meta: {
      last_sync: m[0] || null,
      first_date: m[1] || null,
      last_date: m[2] || null,
      all_rows: Number(m[3] || 0),
    },
    locations: locMap,
    fields: ["id", "loc", "date", "time", "status", "from", "to", "dur", "cid"],
    // [message_id, location_id, YYYY-MM-DD, HH:MM:SS, status, from, to, seconds, contact_id]
    rows: calls.rows.map((r) => [
      r[0], r[1], r[2], r[3], r[4], r[5], r[6],
      r[7] === null || r[7] === undefined ? null : Number(r[7]),
      r[8] || null,
    ]),
  };
}

/* --------------------------------------------------------------- handler */

const JSON_HEADERS = {
  "Content-Type": "application/json; charset=utf-8",
  // The widget is embedded cross-origin in the dashboard iframe.
  "Access-Control-Allow-Origin": "*",
};

export default {
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

    if (url.pathname === "/api/data") {
      const bust = url.searchParams.get("refresh") === "1";
      const cache = caches.default;
      const cacheKey = new Request(new URL("/api/data", url.origin).toString(), {
        method: "GET",
      });

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
