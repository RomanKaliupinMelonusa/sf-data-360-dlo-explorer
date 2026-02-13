/**
 * DLO Explorer (Data Cloud / Data 360) - Reference backend
 *
 * - OAuth to Salesforce (authorization code)
 * - Exchange SF token -> Data Cloud token via /services/a360/token
 * - List DLOs/fields via GET /api/v1/metadata
 * - Preview rows via POST /api/v1/query (Query V2)
 */

import "dotenv/config";
import express from "express";
import cookieSession from "cookie-session";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import path from "path";
import { fileURLToPath } from "url";
import crypto from "crypto";

const IS_PROD = process.env.NODE_ENV === "production";

const app = express();
if (IS_PROD) app.set("trust proxy", 1);
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));

app.use(
  cookieSession({
    name: "session",
    keys: [process.env.SESSION_SECRET || "dev-secret-change-me"],
    httpOnly: true,
    sameSite: "lax",
    secure: IS_PROD,
    // No maxAge — cookie expires when the browser is closed (session cookie)
  })
);

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.static(path.join(__dirname, "public")));

const apiLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests, please try again later." },
});
app.use("/api/", apiLimiter);
app.use("/auth/", apiLimiter);

// Stricter limiter for site-login to prevent brute-force
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many login attempts, please try again later." },
});

// ---- Site-access gate (username / password) ----

const SITE_USER = process.env.SITE_USER || "";
const SITE_PASS_HASH = process.env.SITE_PASS_HASH || ""; // SHA-256 hex of the password

if (!SITE_USER || !SITE_PASS_HASH) {
  console.warn(
    "⚠  SITE_USER / SITE_PASS_HASH not set – site-access gate is DISABLED.\n" +
    "   Generate a hash:  node -e \"console.log(require('crypto').createHash('sha256').update('YOUR_PASSWORD').digest('hex'))\""
  );
}

function siteGateEnabled() {
  return !!(SITE_USER && SITE_PASS_HASH);
}

function verifySitePassword(plain) {
  const hash = crypto.createHash("sha256").update(String(plain)).digest("hex");
  // Constant-time comparison to prevent timing attacks
  return crypto.timingSafeEqual(Buffer.from(hash, "hex"), Buffer.from(SITE_PASS_HASH, "hex"));
}

// Endpoints for site gate (placed BEFORE the gate middleware so they are accessible)
app.post("/site/login", loginLimiter, (req, res) => {
  if (!siteGateEnabled()) return res.json({ ok: true });
  const { user, pass } = req.body || {};
  if (
    typeof user === "string" &&
    typeof pass === "string" &&
    user === SITE_USER &&
    verifySitePassword(pass)
  ) {
    req.session.siteAuthed = true;
    return res.json({ ok: true });
  }
  // Generic message — don't reveal which field was wrong
  return res.status(401).json({ error: "Invalid credentials." });
});

app.get("/site/status", (req, res) => {
  res.json({ gateEnabled: siteGateEnabled(), authed: !!req.session.siteAuthed });
});

app.post("/site/logout", (req, res) => {
  req.session = null;
  res.json({ ok: true });
});

// Middleware: block everything else until site login is complete
app.use((req, res, next) => {
  if (!siteGateEnabled()) return next();
  if (req.session.siteAuthed) return next();

  // Allow the auth callback through (Salesforce redirects back here)
  if (req.path === "/auth/callback") return next();

  // For API / auth routes return 401 JSON
  if (req.path.startsWith("/api/") || req.path.startsWith("/auth/")) {
    return res.status(401).json({ error: "Site login required." });
  }

  // For page requests, serve index.html (the JS inside handles the gate UI)
  next();
});

const SF_LOGIN_URL = normalizeBaseUrl(process.env.SF_LOGIN_URL || "https://login.salesforce.com");
const CLIENT_ID = process.env.SF_CLIENT_ID;
const CLIENT_SECRET = process.env.SF_CLIENT_SECRET;
const REDIRECT_URI = process.env.SF_REDIRECT_URI || "http://localhost:3001/auth/callback";
const SCOPES =
  process.env.SF_SCOPES ||
  "api refresh_token offline_access cdp_query_api";

if (!CLIENT_ID || !CLIENT_SECRET) {
  console.warn("Missing SF_CLIENT_ID / SF_CLIENT_SECRET in environment.");
}

function normalizeBaseUrl(u) {
  if (!u) return "";
  let s = String(u).trim().replace(/\/+$/g, "");
  if (!/^https?:\/\//i.test(s)) s = "https://" + s;
  return s;
}

function nowMs() {
  return Date.now();
}

async function sfTokenFromCode(code, verifier) {
  const codeVerifier = (verifier || "").toString();
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET,
    redirect_uri: REDIRECT_URI,
    code,
    code_verifier: codeVerifier,
  });

  const resp = await fetch(`${SF_LOGIN_URL}/services/oauth2/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });

  if (!resp.ok) {
    throw new Error(`Salesforce token exchange failed: ${resp.status} ${await resp.text()}`);
  }
  return resp.json();
}

async function sfTokenFromRefresh(refresh_token) {
  const body = new URLSearchParams({
    grant_type: "refresh_token",
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET,
    refresh_token,
  });

  const resp = await fetch(`${SF_LOGIN_URL}/services/oauth2/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });

  if (!resp.ok) {
    throw new Error(`Salesforce refresh failed: ${resp.status} ${await resp.text()}`);
  }
  return resp.json();
}

/**
 * Exchange Salesforce access token for Data Cloud token:
 * POST {instance_url}/services/a360/token
 * grant_type=urn:salesforce:grant-type:external:cdp
 * subject_token=<SF access_token>
 * subject_token_type=urn:ietf:params:oauth:token-type:access_token
 */
async function exchangeToDataCloudToken(sfInstanceUrl, sfAccessToken) {
  const body = new URLSearchParams({
    grant_type: "urn:salesforce:grant-type:external:cdp",
    subject_token: sfAccessToken,
    subject_token_type: "urn:ietf:params:oauth:token-type:access_token",
  });

  if (process.env.SF_DATASPACE) {
    body.set("dataspace", process.env.SF_DATASPACE);
  }

  const resp = await fetch(`${sfInstanceUrl}/services/a360/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });

  if (!resp.ok) {
    throw new Error(`Data Cloud token exchange failed: ${resp.status} ${await resp.text()}`);
  }
  return resp.json();
}

async function ensureTokens(req) {
  if (!req.session.auth) return;

  const auth = req.session.auth;
  const ageMs = nowMs() - (auth.sf_obtained_at_ms || 0);
  if (ageMs > 50 * 60 * 1000 && auth.refresh_token) {
    const refreshed = await sfTokenFromRefresh(auth.refresh_token);
    auth.sf_access_token = refreshed.access_token;
    auth.sf_instance_url = normalizeBaseUrl(refreshed.instance_url || auth.sf_instance_url);
    auth.sf_obtained_at_ms = nowMs();
  }

  if (!auth.dc_access_token || nowMs() > (auth.dc_expires_at_ms || 0) - 30_000) {
    const dc = await exchangeToDataCloudToken(auth.sf_instance_url, auth.sf_access_token);

    const dcUrl = normalizeBaseUrl(dc.instance_url);
    if (!dcUrl) {
      throw new Error(`Data Cloud token response missing instance_url. Raw response: ${JSON.stringify(dc)}`);
    }

    auth.dc_access_token = dc.access_token;
    auth.dc_instance_url = dcUrl;
    auth.dc_expires_at_ms = nowMs() + (dc.expires_in || 3600) * 1000;
  }

  req.session.auth = auth;
}

function requireAuth(req, res, next) {
  if (!req.session.auth?.sf_access_token) return res.status(401).json({ error: "Not logged in" });
  next();
}

// ---- Auth routes ----

app.get("/auth/login", (req, res) => {
  const state = crypto.randomUUID();
  req.session.oauth_state = state;

  const verifier = crypto.randomBytes(32).toString("base64url");
  const challenge = crypto
    .createHash("sha256")
    .update(verifier)
    .digest("base64url");

  req.session.pkce_verifier = verifier;

  const params = new URLSearchParams({
    response_type: "code",
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    scope: SCOPES,
    state,
    code_challenge: challenge,
    code_challenge_method: "S256",
  });

  res.redirect(`${SF_LOGIN_URL}/services/oauth2/authorize?${params.toString()}`);
});

app.get("/auth/callback", async (req, res) => {
  try {
    const { code, state } = req.query;
    if (!code) return res.status(400).send("Missing code");
    if (!state || state !== req.session.oauth_state) return res.status(400).send("State mismatch");

    const tok = await sfTokenFromCode(code, req.session.pkce_verifier);

    req.session.auth = {
      sf_access_token: tok.access_token,
      sf_instance_url: tok.instance_url,
      refresh_token: tok.refresh_token,
      sf_obtained_at_ms: nowMs(),
    };

    await ensureTokens(req);

    res.redirect("/");
  } catch (e) {
    console.error("Auth callback error:", e);
    res.status(500).send(IS_PROD ? "Authentication failed. Please try again." : String(e));
  }
});

app.post("/auth/logout", (req, res) => {
  req.session = null;
  res.json({ ok: true });
});

// ---- App API ----

app.get("/api/status", async (req, res) => {
  try {
    if (!req.session.auth?.sf_access_token) return res.json({ loggedIn: false });
    await ensureTokens(req);
    res.json({
      loggedIn: true,
      dc_instance_url: req.session.auth.dc_instance_url,
      dc_expires_at_ms: req.session.auth.dc_expires_at_ms,
    });
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

/**
 * List DLOs using Metadata API:
 * GET {dc_instance_url}/api/v1/metadata?entityType=DataLakeObject
 */
app.get("/api/dlos", requireAuth, async (req, res) => {
  try {
    await ensureTokens(req);
    const { dc_instance_url, dc_access_token } = req.session.auth;

    const url = new URL(`${dc_instance_url}/api/v1/metadata`);
    url.searchParams.set("entityType", "DataLakeObject");

    const resp = await fetch(url, {
      headers: { Authorization: `Bearer ${dc_access_token}` },
    });

    if (!resp.ok) throw new Error(`Metadata API failed: ${resp.status} ${await resp.text()}`);
    const json = await resp.json();

    const list = (json.metadata || [])
      .map((m) => ({
        name: m.name,
        displayName: m.displayName || m.name,
        category: m.category,
      }))
      .sort((a, b) => a.displayName.localeCompare(b.displayName));

    res.json({ dlos: list });
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

/**
 * Get full DLO metadata (fields, keys, etc.)
 * GET {dc_instance_url}/api/v1/metadata?entityType=DataLakeObject&entityName=<name>
 */
app.get("/api/dlo/:name/meta", requireAuth, async (req, res) => {
  try {
    await ensureTokens(req);
    const { dc_instance_url, dc_access_token } = req.session.auth;

    const url = new URL(`${dc_instance_url}/api/v1/metadata`);
    url.searchParams.set("entityType", "DataLakeObject");
    url.searchParams.set("entityName", req.params.name);

    const resp = await fetch(url, {
      headers: { Authorization: `Bearer ${dc_access_token}` },
    });

    if (!resp.ok) throw new Error(`Metadata API failed: ${resp.status} ${await resp.text()}`);
    const json = await resp.json();

    const entity = (json.metadata || [])[0];
    if (!entity) return res.status(404).json({ error: "DLO not found" });

    res.json({ entity });
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

/**
 * Preview query using Query V2:
 * POST {dc_instance_url}/api/v1/query?limit=&offset=&orderby=
 * body: { sql: "SELECT ... FROM <DLO>" }
 */
app.post("/api/dlo/:name/preview", requireAuth, async (req, res) => {
  try {
    await ensureTokens(req);
    const { dc_instance_url, dc_access_token } = req.session.auth;

    const { fields, limit, offset, orderby, where, sql } = req.body;

    const lim = Math.max(1, Math.min(Number(limit || 100), 5000));
    const off = Math.max(0, Number(offset || 0));
    const order = typeof orderby === "string" ? orderby : "";

    const safeIdent = (s) => typeof s === "string" && /^[A-Za-z0-9_]+(__[a-z]{3}|__c)?$/i.test(s);

    const dloName = req.params.name;
    if (!safeIdent(dloName)) return res.status(400).json({ error: "Invalid DLO name" });

    const selected = Array.isArray(fields) && fields.length ? fields : ["*"];

    if (selected[0] !== "*") {
      for (const f of selected) {
        if (!safeIdent(f)) return res.status(400).json({ error: `Invalid field: ${f}` });
      }
    }

    let whereClause = "";
    if (typeof where === "string" && where.trim()) {
      if (!/^[A-Za-z0-9_'"= <>!%().:-]+$/i.test(where)) {
        return res.status(400).json({ error: "Unsafe WHERE clause characters detected" });
      }
      whereClause = ` WHERE ${where.trim()}`;
    }

    const selectClause =
      selected[0] === "*"
        ? "*"
        : selected.map((f) => `"${f.replaceAll('"', '""')}"`).join(", ");

    // Build ORDER BY clause with quoted identifier (only for auto-built SQL)
    let orderByClause = "";
    if (order) {
      const parts = order.trim().split(/\s+/);
      const colName = parts[0];
      const dir = /^desc$/i.test(parts[1] || "") ? "DESC" : "ASC";
      if (safeIdent(colName)) {
        orderByClause = ` ORDER BY "${colName.replaceAll('"', '""')}" ${dir} NULLS LAST`;
      }
    }

    const builtSql = `SELECT ${selectClause} FROM "${dloName.replaceAll('"', '""')}"${whereClause}${orderByClause}`;
    let finalSql = builtSql;
    if (typeof sql === "string" && sql.trim()) {
      const normalized = sql.trim();
      if (!/^SELECT\s/i.test(normalized)) {
        return res.status(400).json({ error: "Custom SQL must be a SELECT statement." });
      }
      // Block dangerous keywords
      if (/\b(INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|TRUNCATE|EXEC|MERGE)\b/i.test(normalized)) {
        return res.status(400).json({ error: "Mutation statements are not allowed." });
      }
      finalSql = normalized;
    }

    const url = new URL(`${dc_instance_url}/api/v1/query`);
    url.searchParams.set("limit", String(lim));
    url.searchParams.set("offset", String(off));

    const resp = await fetch(url, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${dc_access_token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ sql: finalSql }),
    });

    if (!resp.ok) throw new Error(`Query API failed: ${resp.status} ${await resp.text()}`);
    const json = await resp.json();

    res.json({ sql: finalSql, result: json });
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

// Vercel imports this module as a serverless function — export the app.
export default app;

// Only listen when running locally (not on Vercel).
if (!process.env.VERCEL) {
  const PORT = Number(process.env.PORT || 3001);
  app.listen(PORT, () => console.log(`DLO Explorer server running on http://localhost:${PORT}`));
}
