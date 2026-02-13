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

// ---- Connect API helpers (for Related Objects / lineage) ----

function pickList(json) {
  if (!json) return [];
  return (
    json.data || json.members || json.dataModelObjectMappings ||
    json.fieldSourceTargetRelationships || json.items ||
    json.results || json.records || json.metadata || []
  );
}

function safeStr(v) {
  if (v == null) return "";
  return String(v);
}

async function sfGetLatestApiVersion(sfInstanceUrl, sfAccessToken) {
  const resp = await fetch(`${normalizeBaseUrl(sfInstanceUrl)}/services/data`, {
    headers: { Authorization: `Bearer ${sfAccessToken}` },
  });
  if (!resp.ok) throw new Error(`Failed to list SF API versions: ${resp.status} ${await resp.text()}`);
  const versions = await resp.json();
  const best = (versions || [])
    .map((v) => safeStr(v.version))
    .filter(Boolean)
    .sort((a, b) => parseFloat(b) - parseFloat(a))[0];
  return best || "60.0";
}

async function tryFetchJson(url, token, timeoutMs = 8000) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const resp = await fetch(url, {
      headers: { Authorization: `Bearer ${token}` },
      signal: ctrl.signal,
    });
    const text = await resp.text();
    let json = null;
    try { json = text ? JSON.parse(text) : null; } catch {}
    return { resp, text, json };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Resolve Data 360 Connect REST API base URL.
 * Uses DC_CONNECT_BASE_URL if set, otherwise probes common URL patterns.
 */
async function resolveConnectApiBase(req) {
  await ensureTokens(req);
  const auth = req.session.auth;

  if (auth.dc_connect_base_url && auth.dc_connect_token_kind) {
    return { baseUrl: auth.dc_connect_base_url, tokenKind: auth.dc_connect_token_kind };
  }

  if (process.env.DC_CONNECT_BASE_URL) {
    const baseUrl = normalizeBaseUrl(process.env.DC_CONNECT_BASE_URL);
    const tokenKind = (process.env.DC_CONNECT_TOKEN || "dc").toLowerCase() === "sf" ? "sf" : "dc";
    auth.dc_connect_base_url = baseUrl;
    auth.dc_connect_token_kind = tokenKind;
    req.session.auth = auth;
    return { baseUrl, tokenKind };
  }

  const sfVersion = await sfGetLatestApiVersion(auth.sf_instance_url, auth.sf_access_token);
  const dc = normalizeBaseUrl(auth.dc_instance_url);
  const sf = normalizeBaseUrl(auth.sf_instance_url);

  const candidates = [
    // SSOT namespace on SF org host (correct per Data 360 Connect REST API docs)
    { base: `${sf}/services/data/v${sfVersion}`, tokenKind: "sf" },
    // Legacy Connect namespace variants on SF org host
    { base: `${sf}/services/data/v${sfVersion}/connect/cdp`, tokenKind: "sf" },
    { base: `${sf}/services/data/v${sfVersion}/connect/dataCloud`, tokenKind: "sf" },
    // DC tenant host (unlikely but try last)
    { base: `${dc}/services/data/v${sfVersion}`, tokenKind: "dc" },
    { base: `${dc}/api/v1`, tokenKind: "dc" },
  ];

  const mappingPaths = [
    // SSOT namespace paths (primary)
    "ssot/data-model-object-mappings",
    "ssot/dataModelObjectMappings",
    // Legacy / Connect namespace paths
    process.env.DC_CONNECT_MAPPING_COLLECTION_PATH || "dataModelObjectMappings",
    "cdpDataModelObjectMappings",
  ];
  // Deduplicate in case the env var equals one of the defaults
  const uniquePaths = [...new Set(mappingPaths)];

  const probeLog = [];
  for (const c of candidates) {
    const token = c.tokenKind === "dc" ? auth.dc_access_token : auth.sf_access_token;
    for (const mp of uniquePaths) {
      const probeUrl = `${c.base}/${mp}`;
      try {
        const { resp } = await tryFetchJson(probeUrl, token);
        probeLog.push({ url: probeUrl, tokenKind: c.tokenKind, status: resp.status });
        if (resp.status === 200 || resp.status === 400) {
          auth.dc_connect_base_url = c.base;
          auth.dc_connect_token_kind = c.tokenKind;
          auth.dc_connect_mapping_path = mp;
          req.session.auth = auth;
          return { baseUrl: c.base, tokenKind: c.tokenKind, mappingPath: mp, probeLog };
        }
      } catch (probeErr) {
        probeLog.push({ url: probeUrl, tokenKind: c.tokenKind, error: probeErr.name || String(probeErr) });
      }
    }
  }

  const err = new Error(
    "Unable to auto-discover Data 360 Connect API base URL. Set DC_CONNECT_BASE_URL + DC_CONNECT_TOKEN env vars."
  );
  err.probeLog = probeLog;
  throw err;
}

async function connectApiGet(req, relPath, searchParams = {}) {
  const { baseUrl, tokenKind } = await resolveConnectApiBase(req);
  const auth = req.session.auth;
  const token = tokenKind === "dc" ? auth.dc_access_token : auth.sf_access_token;
  const url = new URL(`${baseUrl.replace(/\/+$/g, "")}/${relPath.replace(/^\/+/g, "")}`);
  for (const [k, v] of Object.entries(searchParams)) {
    if (v !== undefined && v !== null && `${v}`.length) url.searchParams.set(k, String(v));
  }
  const { resp, text, json } = await tryFetchJson(url.toString(), token);
  if (!resp.ok) throw new Error(`Connect API GET failed: ${resp.status} ${text}`);
  return json;
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

/**
 * Related Objects (Lineage) for a DLO:
 * - Find DLO → DMO mappings via Connect API
 * - For each mapped DMO, pull metadata relationships
 * - Backfill join fields from fieldSourceTargetRelationships if needed
 */
app.get("/api/dlo/:name/related-objects", requireAuth, async (req, res) => {
  try {
    await ensureTokens(req);
    const auth = req.session.auth;
    const dloName = req.params.name;

    const mappingCollectionPath =
      req.session.auth?.dc_connect_mapping_path ||
      process.env.DC_CONNECT_MAPPING_COLLECTION_PATH ||
      "ssot/data-model-object-mappings";
    const relCollectionPath =
      process.env.DC_CONNECT_FIELD_REL_COLLECTION_PATH ||
      "ssot/field-source-target-relationships";

    // 1) Get all DLO→DMO mappings
    let mappings = [];
    let connectAvailable = true;
    let connectProbeLog = [];
    try {
      const mappingsJson = await connectApiGet(req, mappingCollectionPath);
      mappings = pickList(mappingsJson);
    } catch (e) {
      // Connect API may not be available — fall back to metadata-only mode
      connectAvailable = false;
      connectProbeLog = e?.probeLog || (e?.cause?.probeLog) || [];
    }

    // Heuristic field extractors (payload shapes vary by org)
    const getMappingId = (m) => m?.id || m?.name || m?.mappingId || m?.developerName || "";
    const getSourceDlo = (m) =>
      m?.sourceDataLakeObjectName || m?.sourceDloName || m?.dataLakeObjectName ||
      m?.sourceObjectName || m?.source?.name || m?.sourceEntityName || "";
    const getTargetDmo = (m) =>
      m?.targetDataModelObjectName || m?.targetDmoName || m?.dataModelObjectName ||
      m?.targetObjectName || m?.target?.name || m?.targetEntityName || "";

    const matched = mappings.filter((m) =>
      safeStr(getSourceDlo(m)).toLowerCase() === dloName.toLowerCase()
    );

    // Field relationship collection (lazy-loaded)
    let fieldRels = null;
    async function ensureFieldRelsLoaded() {
      if (fieldRels) return;
      try {
        const fieldRelJson = await connectApiGet(req, relCollectionPath);
        fieldRels = pickList(fieldRelJson);
      } catch {
        fieldRels = [];
      }
    }

    const relSourceDmo = (r) => r?.sourceDataModelObjectName || r?.sourceDmoName || r?.sourceObjectName || r?.source?.name || "";
    const relTargetDmo = (r) => r?.targetDataModelObjectName || r?.targetDmoName || r?.targetObjectName || r?.target?.name || "";
    const relSourceField = (r) => r?.sourceFieldName || r?.sourceField || r?.source?.fieldName || "";
    const relTargetField = (r) => r?.targetFieldName || r?.targetField || r?.target?.fieldName || "";

    // 2) For each mapping, collect DMO relationships
    const out = [];

    // Helper to fetch DMO metadata relationships
    async function fetchDmoRelationships(dmoName) {
      const metaUrl = new URL(`${auth.dc_instance_url}/api/v1/metadata`);
      metaUrl.searchParams.set("entityType", "DataModelObject");
      metaUrl.searchParams.set("entityName", dmoName);
      const metaResp = await fetch(metaUrl, { headers: { Authorization: `Bearer ${auth.dc_access_token}` } });
      if (!metaResp.ok) return null;
      const metaJson = await metaResp.json();
      return (metaJson.metadata || [])[0] || null;
    }

    function normalizeRelationships(metaRels, dmoName) {
      return (metaRels || []).map((r) => {
        const fromEntity = r?.fromEntity || "";
        const toEntity = r?.toEntity || "";
        const isOutgoing = fromEntity.toLowerCase() === dmoName.toLowerCase();
        const relatedName = isOutgoing ? toEntity : fromEntity;

        const metaJoinPairs = [];
        if (r?.fromEntityAttribute && r?.toEntityAttribute) {
          metaJoinPairs.push({
            sourceField: r.fromEntityAttribute,
            targetField: r.toEntityAttribute,
          });
        } else {
          const srcFields = r?.sourceFields || r?.sourceFieldNames || (r?.sourceField ? [r.sourceField] : []);
          const tgtFields = r?.targetFields || r?.targetFieldNames || (r?.targetField ? [r.targetField] : []);
          const n = Math.min(srcFields.length, tgtFields.length);
          for (let i = 0; i < n; i++) {
            metaJoinPairs.push({ sourceField: srcFields[i], targetField: tgtFields[i] });
          }
        }

        return {
          relatedDmoName: relatedName,
          relationshipName: r?.name || r?.relationshipName || r?.developerName || "",
          type: r?.type || r?.relationshipType || r?.cardinality || "",
          direction: isOutgoing ? "outgoing" : "incoming",
          join: metaJoinPairs,
          raw: r,
        };
      });
    }

    if (matched.length > 0) {
      // We have Connect API mappings
      for (const m of matched) {
        const mappingId = getMappingId(m);
        const dmoName = getTargetDmo(m);
        if (!dmoName) continue;

        // Fetch mapping detail (best effort)
        let fieldMappings = [];
        if (mappingId) {
          try {
            const detail = await connectApiGet(req, `${mappingCollectionPath}/${encodeURIComponent(mappingId)}`);
            const fm = detail?.fieldMappings || detail?.fieldMapping || detail?.mappings || detail?.fields || [];
            fieldMappings = Array.isArray(fm) ? fm : [];
          } catch {}
        }

        // Fetch DMO metadata
        const entity = await fetchDmoRelationships(dmoName);
        const relatedObjects = normalizeRelationships(entity?.relationships, dmoName);

        // Backfill join fields from fieldSourceTargetRelationships
        const needsBackfill = relatedObjects.some((x) => !x.join.length);
        if (needsBackfill) {
          await ensureFieldRelsLoaded();
          const joinMap = new Map();
          for (const r of fieldRels) {
            const s = safeStr(relSourceDmo(r));
            const t = safeStr(relTargetDmo(r));
            if (!s || !t) continue;
            const key = `${s}::${t}`;
            const pair = { sourceField: relSourceField(r), targetField: relTargetField(r) };
            if (!pair.sourceField || !pair.targetField) continue;
            if (!joinMap.has(key)) joinMap.set(key, []);
            joinMap.get(key).push(pair);
          }
          for (const ro of relatedObjects) {
            if (ro.join.length) continue;
            ro.join = joinMap.get(`${dmoName}::${ro.relatedDmoName}`) ||
                      joinMap.get(`${ro.relatedDmoName}::${dmoName}`) || [];
          }
        }

        out.push({ dmoName, mappingSummary: m, fieldMappings, relatedObjects });
      }
    } else {
      // No Connect API — scan all DMO metadata for relationships involving this DLO
      try {
        const allDmoUrl = new URL(`${auth.dc_instance_url}/api/v1/metadata`);
        allDmoUrl.searchParams.set("entityType", "DataModelObject");
        const allDmoResp = await fetch(allDmoUrl, { headers: { Authorization: `Bearer ${auth.dc_access_token}` } });
        if (allDmoResp.ok) {
          const allDmoJson = await allDmoResp.json();
          const allDmos = allDmoJson.metadata || [];
          const dloLower = dloName.toLowerCase();
          const dloBase = dloLower.replace(/__dll$/, "");
          const dloBaseShort = dloBase.replace(/_\d+$/, ""); // strip org-id suffix for SFMC DLOs

          for (const dmo of allDmos) {
            const dmoLower = (dmo.name || "").toLowerCase();
            const dmoBase = dmoLower.replace(/__dlm$/, "");

            // 1) Direct reference: a DMO relationship mentions this DLO by name
            const hasDirectRef = (dmo.relationships || []).some((r) => {
              const f = (r.fromEntity || "").toLowerCase();
              const t = (r.toEntity || "").toLowerCase();
              return f === dloLower || t === dloLower;
            });

            // 2) Name heuristic: DLO base name matches DMO base name
            //    e.g. ssot__Individual__dll  ↔  ssot__Individual__dlm
            //    e.g. sfmc_email_click_12345__dll  ↔  sfmc_email_click__dlm
            const isNameRelated =
              (dloBase === dmoBase || dloBaseShort === dmoBase) && dmoBase.length > 0;

            if (hasDirectRef || isNameRelated) {
              const relatedObjects = normalizeRelationships(dmo.relationships || [], dmo.name);
              out.push({
                dmoName: dmo.name,
                displayName: dmo.displayName || dmo.name,
                category: dmo.category || "",
                fieldCount: (dmo.fields || []).length,
                mappingSummary: null,
                fieldMappings: [],
                relatedObjects,
                discoveredVia: hasDirectRef ? "metadata-reference" : "name-heuristic",
              });
            }
          }
        }
      } catch (scanErr) {
        console.warn("DMO metadata scan failed:", scanErr.message);
      }
    }

    // 3) Always include DLO's own metadata relationships as a fallback/supplement
    const dloMetaUrl = new URL(`${auth.dc_instance_url}/api/v1/metadata`);
    dloMetaUrl.searchParams.set("entityType", "DataLakeObject");
    dloMetaUrl.searchParams.set("entityName", dloName);
    const dloMetaResp = await fetch(dloMetaUrl, { headers: { Authorization: `Bearer ${auth.dc_access_token}` } });
    let dloRelationships = [];
    let rawDloRelationships = [];
    if (dloMetaResp.ok) {
      const dloMetaJson = await dloMetaResp.json();
      const dloEntity = (dloMetaJson.metadata || [])[0];
      rawDloRelationships = dloEntity?.relationships || [];
      if (rawDloRelationships.length) {
        dloRelationships = normalizeRelationships(rawDloRelationships, dloName);
      }
    }

    res.json({
      dlo: dloName,
      mappedDmos: out,
      dloRelationships,
      connectAvailable,
      debug: {
        connectBaseResolved: req.session.auth.dc_connect_base_url || null,
        connectTokenKind: req.session.auth.dc_connect_token_kind || null,
        rawDloRelationshipCount: rawDloRelationships.length,
        dmoScanMatches: out.filter((d) => d.discoveredVia).length,
        totalDmoMatches: out.length,
        connectProbeLog,
      },
    });
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

// Debug: check Connect API base URL resolution + SSOT availability
app.get("/api/debug/connect", requireAuth, async (req, res) => {
  try {
    const resolved = await resolveConnectApiBase(req);
    res.json({ ok: true, ...resolved });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e), probeLog: e.probeLog || [] });
  }
});

app.get("/api/connect/status", requireAuth, async (req, res) => {
  try {
    await ensureTokens(req);
    const auth = req.session.auth;
    const sfVersion = await sfGetLatestApiVersion(auth.sf_instance_url, auth.sf_access_token);
    const sfBase = `${normalizeBaseUrl(auth.sf_instance_url)}/services/data/v${sfVersion}`;

    // Check if /services/data/vXX.X/ lists an "ssot" resource
    let ssotAvailable = false;
    let resourceKeys = [];
    try {
      const { resp, json } = await tryFetchJson(`${sfBase}/`, auth.sf_access_token);
      if (resp.ok && json) {
        resourceKeys = Object.keys(json);
        ssotAvailable = resourceKeys.includes("ssot");
      }
    } catch {}

    // Quick probe of the SSOT mapping endpoint
    let ssotMappingProbe = null;
    try {
      const { resp } = await tryFetchJson(
        `${sfBase}/ssot/data-model-object-mappings`,
        auth.sf_access_token
      );
      ssotMappingProbe = { status: resp.status };
    } catch (e) {
      ssotMappingProbe = { error: e.name || String(e) };
    }

    res.json({
      sf_instance_url: auth.sf_instance_url,
      dc_instance_url: auth.dc_instance_url,
      sf_api_version: sfVersion,
      sf_rest_base: sfBase,
      ssot_available: ssotAvailable,
      ssot_mapping_probe: ssotMappingProbe,
      sf_resource_keys: resourceKeys,
    });
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
