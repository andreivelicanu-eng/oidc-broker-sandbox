import dotenv from "dotenv";
import express from "express";
import helmet from "helmet";
import cookieParser from "cookie-parser";
import rateLimit from "express-rate-limit";
import { z } from "zod";
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Prisma } from "@prisma/client";
import { SAML } from "@node-saml/node-saml";
import { parseStringPromise } from "xml2js";
import { prisma } from "./prisma.js";
import { asyncHandler, httpError, safeRelativeRedirect } from "./http.js";
import {
  decryptAes256Gcm,
  encryptAes256Gcm,
  getAesKeyFromBase64,
  getSessionSigningKeyFromBase64,
  randomUrlSafeString,
  sha256Base64Url,
  signHmacSha256Base64Url,
} from "./crypto.js";
import { buildAuthorizeUrl, exchangeCodeForTokens, verifyIdToken } from "./oktaOidc.js";
import { getDiscovery } from "./oidcCache.js";
import { getEnv } from "./env.js";
import {
  auth0IssuerFromDomain,
  buildAuth0AuthorizeUrl,
  exchangeAuth0Code,
  parseAllowedEmailsCsv,
  verifyAuth0IdToken,
  workspaceFromAuth0Payload,
} from "./auth0Admin.js";
import { SignJWT } from "jose";

// Prefer values from the local .env file over shell exports for local dev.
dotenv.config({ override: true });

const env = getEnv();
const aesKey = getAesKeyFromBase64(env.TENANT_SECRET_ENCRYPTION_KEY);
const sessionKey = getSessionSigningKeyFromBase64(env.SESSION_SIGNING_KEY);

const app = express();
app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "200kb" }));
app.use(cookieParser());

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
app.use("/admin-assets", express.static(path.join(__dirname, "..", "public", "admin-assets"), { maxAge: "7d" }));

const authLimiter = rateLimit({ windowMs: 60_000, limit: 30, standardHeaders: true, legacyHeaders: false });
app.use("/t/:tenantId/login", authLimiter);
app.use("/oidc/callback", authLimiter);

const adminLimiter = rateLimit({ windowMs: 60_000, limit: 60, standardHeaders: true, legacyHeaders: false });
app.use("/admin", adminLimiter);

function normalizeOktaOrgUrl(raw: string): string {
  const v = String(raw ?? "").trim();
  const withScheme = v.includes("://") ? v : `https://${v}`;
  const inputUrl = new URL(withScheme);
  let orgHost = inputUrl.host;
  // Okta Admin Console domains often look like "<org>-admin.okta.com".
  orgHost = orgHost.replace("-admin.okta.com", ".okta.com").replace("-admin.oktapreview.com", ".oktapreview.com");
  return `${inputUrl.protocol}//${orgHost}`;
}

async function extractOktaIdpFromMetadata(
  xml: string,
): Promise<{ idpSsoUrl: string; idpCert: string; idpEntityId?: string }> {
  const s = String(xml ?? "");
  const entityId = s.match(/\bentityID="([^"]+)"/)?.[1];

  // Regex first (namespace-tolerant).
  const ssoUrl =
    s.match(/<(?:\w+:)?SingleSignOnService\b[^>]*\bLocation="([^"]+)"[^>]*>/)?.[1] ??
    s.match(/\bSingleSignOnService\b[^>]*\bLocation="([^"]+)"/)?.[1] ??
    "";
  const certB64 =
    s.match(/<(?:\w+:)?X509Certificate>([^<]+)<\/(?:\w+:)?X509Certificate>/)?.[1]?.trim?.() ?? "";

  if (ssoUrl && certB64) return { idpSsoUrl: ssoUrl, idpCert: certB64, idpEntityId: entityId };

  // xml2js fallback.
  try {
    const doc: any = await parseStringPromise(s, {
      explicitArray: true,
      tagNameProcessors: [(name: string) => name.replace(/^.*:/, "")],
      attrNameProcessors: [(name: string) => name.replace(/^.*:/, "")],
      explicitCharkey: true,
      charkey: "_",
      mergeAttrs: true,
      trim: true,
    });

    const entity =
      doc?.EntityDescriptor ??
      doc?.EntitiesDescriptor?.[0]?.EntityDescriptor?.[0] ??
      doc?.EntitiesDescriptor?.EntityDescriptor;
    const ent = Array.isArray(entity) ? entity[0] : entity;
    const idp = ent?.IDPSSODescriptor?.[0] ?? ent?.IDPSSODescriptor;
    const sso = (idp?.SingleSignOnService ?? [])[0] ?? idp?.SingleSignOnService?.[0];
    const parsedSsoUrl = String(sso?.Location ?? sso?.location ?? "");

    let parsedCert = "";
    const keyDesc = (idp?.KeyDescriptor ?? []).map((x: any) => x);
    for (const kd of keyDesc) {
      const ki = kd?.KeyInfo?.[0] ?? kd?.KeyInfo;
      const xd = ki?.X509Data?.[0] ?? ki?.X509Data;
      const cert = xd?.X509Certificate?.[0] ?? xd?.X509Certificate;
      if (cert) {
        parsedCert = String(cert?._ ?? cert ?? "").trim();
        if (parsedCert) break;
      }
    }

    if (parsedSsoUrl && parsedCert) return { idpSsoUrl: parsedSsoUrl, idpCert: parsedCert, idpEntityId: entityId };
  } catch {
    // fall through
  }

  throw httpError(400, "Could not parse IdP SSO URL / signing cert from metadata");
}

function samlAcsUrl(): string {
  return `${env.PUBLIC_BASE_URL.replace(/\/$/, "")}/saml/acs`;
}

function samlSpEntityId(tenantId: string): string {
  return `${env.PUBLIC_BASE_URL.replace(/\/$/, "")}/t/${encodeURIComponent(tenantId)}/saml/metadata`;
}

function normalizePemCert(cert: string): string {
  const c = String(cert || "").trim();
  if (!c) return c;
  if (c.includes("BEGIN CERTIFICATE")) return c;
  const wrapped = c.replace(/\s+/g, "").match(/.{1,64}/g)?.join("\n") ?? c;
  return `-----BEGIN CERTIFICATE-----\n${wrapped}\n-----END CERTIFICATE-----`;
}

function buildSamlClient(cfg: { tenantId: string; idpSsoUrl: string; idpCert: string; idpEntityId?: string | null }) {
  return new SAML({
    entryPoint: cfg.idpSsoUrl,
    issuer: samlSpEntityId(cfg.tenantId),
    callbackUrl: samlAcsUrl(),
    idpCert: normalizePemCert(cfg.idpCert),
    wantAssertionsSigned: true,
    wantAuthnResponseSigned: true,
    disableRequestedAuthnContext: true,
    identifierFormat: undefined,
    acceptedClockSkewMs: 120_000,
  } as any);
}

function cookieSecure(): boolean {
  if (env.COOKIE_SECURE === "true") return true;
  try {
    return new URL(env.PUBLIC_BASE_URL).protocol === "https:";
  } catch {
    return false;
  }
}

function setSessionCookie(res: express.Response, sessionId: string) {
  const sig = signHmacSha256Base64Url(sessionId, sessionKey);
  const value = `${sessionId}.${sig}`;
  res.cookie("sid", value, {
    httpOnly: true,
    secure: cookieSecure(),
    sameSite: "lax",
    path: "/",
    maxAge: 1000 * 60 * 60 * 8,
  });
}

async function createSessionJwt(session: { id: string; tenantId: string; subject: string; expiresAt: Date }) {
  const now = Math.floor(Date.now() / 1000);
  const exp = Math.floor(session.expiresAt.getTime() / 1000);
  return await new SignJWT({ sid: session.id, tenantId: session.tenantId })
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .setSubject(session.subject)
    .setIssuedAt(now)
    .setExpirationTime(exp)
    .sign(sessionKey);
}

function clearSessionCookie(res: express.Response) {
  res.clearCookie("sid", { path: "/" });
}

function setAdminCookie(res: express.Response, customerId: string) {
  // Store a short-lived signed marker with a scope (customerId).
  // This prevents customers from seeing each other's tenants in demos.
  const safeCustomer = customerId.trim() || "default";
  // Never embed raw customerId in a dot-delimited string: workspace ids often contain "."
  // (e.g. "acme.prod"), which breaks parsing and makes every workspace look empty on Fly.
  const cidEnc = Buffer.from(safeCustomer, "utf8").toString("base64url");
  const marker = `admin.c2.${cidEnc}.${randomUrlSafeString(16)}.${Date.now()}`;
  const sig = signHmacSha256Base64Url(marker, sessionKey);
  res.cookie("admin", `${marker}.${sig}`, {
    httpOnly: true,
    secure: cookieSecure(),
    sameSite: "lax",
    path: "/admin",
    maxAge: 1000 * 60 * 60 * 12,
  });
}

function clearAdminCookie(res: express.Response) {
  res.clearCookie("admin", { path: "/admin" });
}

function getAdminCustomerId(req: express.Request): string | null {
  const raw = req.cookies?.admin;
  if (typeof raw !== "string") return null;
  const parts = raw.split(".");
  // New: admin.c2.<cidB64url>.<rand>.<ts>.<sig>
  // Legacy: admin.<customerId>.<rand>.<ts>.<sig>
  if (parts.length < 5) return null;
  const sig = parts.pop();
  const marker = parts.join(".");
  if (!sig) return null;
  const expected = signHmacSha256Base64Url(marker, sessionKey);
  if (!cryptoSafeEqual(expected, sig)) return null;
  let customerId = "default";
  if (parts[1] === "c2" && parts.length >= 5) {
    try {
      customerId = Buffer.from(parts[2] ?? "", "base64url").toString("utf8") || "default";
    } catch {
      customerId = "default";
    }
  } else {
    customerId = parts[1] ?? "default";
  }
  return String(customerId || "default");
}

function isAdminAuthed(req: express.Request): boolean {
  return getAdminCustomerId(req) != null;
}

function requireAdmin(req: express.Request) {
  // Prefer cookie-based admin session; also allow header for API usage.
  const header = req.header("x-admin-key");
  if (header && header === env.ADMIN_API_KEY) return;
  if (isAdminAuthed(req)) return;
  throw httpError(401, "Unauthorized");
}

function adminLoginHrefOrDisabled(req: express.Request): { attrs: string; className: string } {
  if (isAdminAuthed(req)) {
    return { attrs: 'aria-disabled="true" tabindex="-1"', className: "pill disabled" };
  }
  return { attrs: 'href="/admin/login"', className: "pill" };
}

async function requireSession(req: express.Request) {
  const raw = req.cookies?.sid;
  if (typeof raw !== "string") throw httpError(401, "Not authenticated");
  const [sessionId, sig] = raw.split(".");
  if (!sessionId || !sig) throw httpError(401, "Not authenticated");
  const expected = signHmacSha256Base64Url(sessionId, sessionKey);
  if (!cryptoSafeEqual(expected, sig)) throw httpError(401, "Not authenticated");

  const session = await prisma.session.findUnique({ where: { id: sessionId } });
  if (!session) throw httpError(401, "Not authenticated");
  if (session.expiresAt.getTime() <= Date.now()) throw httpError(401, "Session expired");
  return session;
}

function cryptoSafeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

const AUTH0_STATE_COOKIE = "admin_auth0_st";
const AUTH0_STATE_TTL_MS = 10 * 60 * 1000;

function signAuth0OAuthState(payload: { state: string; nonce: string; exp: number; redirectUri: string }): string {
  const b = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
  const sig = signHmacSha256Base64Url(b, sessionKey);
  return `${b}.${sig}`;
}

function verifyAuth0OAuthState(raw: string | undefined): { state: string; nonce: string; redirectUri: string } | null {
  if (typeof raw !== "string" || !raw) return null;
  const last = raw.lastIndexOf(".");
  if (last <= 0) return null;
  const b = raw.slice(0, last);
  const sig = raw.slice(last + 1);
  const expected = signHmacSha256Base64Url(b, sessionKey);
  if (!cryptoSafeEqual(expected, sig)) return null;
  let p: { state?: string; nonce?: string; exp?: number; redirectUri?: string };
  try {
    p = JSON.parse(Buffer.from(b, "base64url").toString("utf8")) as {
      state?: string;
      nonce?: string;
      exp?: number;
      redirectUri?: string;
    };
  } catch {
    return null;
  }
  if (!p.state || !p.nonce || typeof p.exp !== "number") return null;
  if (Date.now() > p.exp) return null;
  const fallbackRedirect = `${env.PUBLIC_BASE_URL.replace(/\/$/, "")}/admin/auth/auth0/callback`;
  const redirectUri = typeof p.redirectUri === "string" && p.redirectUri.trim() ? p.redirectUri.trim() : fallbackRedirect;
  return { state: p.state, nonce: p.nonce, redirectUri };
}

const AUTH0_CALLBACK_PATH = "/admin/auth/auth0/callback";

/** Public origin as seen by the browser (proxy-aware). Used so redirect_uri matches Auth0 allowlist when env URL differs. */
function publicOriginFromRequest(req: express.Request): string | null {
  const host = ((req.get("x-forwarded-host") ?? req.get("host") ?? "").split(",")[0] ?? "").trim();
  if (!host || host.includes("/") || host.includes("..")) return null;
  const xfProto = ((req.get("x-forwarded-proto") ?? "").split(",")[0] ?? "").trim().toLowerCase();
  const scheme = xfProto === "https" || (!xfProto && req.protocol === "https") ? "https" : "http";
  return `${scheme}://${host}`;
}

function resolveAuth0RedirectUri(req: express.Request): string {
  const explicit = env.AUTH0_REDIRECT_URI?.trim();
  if (explicit) {
    try {
      const u = new URL(explicit);
      if (u.protocol !== "http:" && u.protocol !== "https:") throw new Error("bad scheme");
      u.hash = "";
      const path = (u.pathname || "").replace(/\/+$/, "") || "";
      return `${u.origin}${path}${u.search}`;
    } catch {
      // fall through to request / PUBLIC_BASE_URL
    }
  }
  const origin = publicOriginFromRequest(req);
  if (origin) return `${origin}${AUTH0_CALLBACK_PATH}`;
  return `${env.PUBLIC_BASE_URL.replace(/\/$/, "")}${AUTH0_CALLBACK_PATH}`;
}

/** Absolute admin login URL (proxy-aware), for Auth0 returnTo / logout. */
function resolveAdminLoginUrl(req: express.Request): string {
  const origin = publicOriginFromRequest(req);
  if (origin) return `${origin}/admin/login`;
  return `${env.PUBLIC_BASE_URL.replace(/\/$/, "")}/admin/login`;
}

function auth0AdminConfigured(): boolean {
  return !!(env.AUTH0_DOMAIN && env.AUTH0_CLIENT_ID && env.AUTH0_CLIENT_SECRET);
}

function getAuth0AdminConfig(redirectUri: string) {
  return {
    issuer: auth0IssuerFromDomain(env.AUTH0_DOMAIN!),
    clientId: env.AUTH0_CLIENT_ID!,
    clientSecret: env.AUTH0_CLIENT_SECRET!,
    redirectUri,
    allowedEmails: parseAllowedEmailsCsv(env.ADMIN_AUTH0_ALLOWED_EMAILS),
    workspaceClaim: env.AUTH0_WORKSPACE_CLAIM,
  };
}

function toJsonSafe(value: unknown, depth = 0): unknown {
  // Convert complex objects (like SAML profile) into JSON-serializable data:
  // drop functions/undefined/symbols and avoid cycles.
  if (depth > 12) return null;
  if (value == null) return value;
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") return value;
  if (typeof value === "bigint") return value.toString();
  if (typeof value === "function" || typeof value === "symbol") return undefined;
  if (value instanceof Date) return value.toISOString();
  if (Array.isArray(value)) {
    const out: unknown[] = [];
    for (const v of value) {
      const vv = toJsonSafe(v, depth + 1);
      if (vv !== undefined) out.push(vv);
    }
    return out;
  }
  if (typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(obj)) {
      const vv = toJsonSafe(v, depth + 1);
      if (vv !== undefined) out[k] = vv;
    }
    return out;
  }
  return String(value);
}

function extractSamlAttributesSimple(xml: string): Record<string, string | string[]> {
  const s = String(xml ?? "");
  const out: Record<string, string | string[]> = {};
  const attrRe = /<(?:\w+:)?Attribute\b[^>]*\bName="([^"]+)"[^>]*>([\s\S]*?)<\/(?:\w+:)?Attribute>/g;
  let m: RegExpExecArray | null;
  while ((m = attrRe.exec(s))) {
    const name = String(m[1] ?? "").trim();
    if (!name) continue;
    const inner = m[2] ?? "";
    const values: string[] = [];
    const valRe = /<(?:\w+:)?AttributeValue\b[^>]*>([\s\S]*?)<\/(?:\w+:)?AttributeValue>/g;
    let v: RegExpExecArray | null;
    while ((v = valRe.exec(inner))) {
      const txt = String(v[1] ?? "").replace(/<[^>]+>/g, "").trim();
      if (txt) values.push(txt);
    }
    if (values.length === 1) out[name] = values[0] ?? "";
    else if (values.length > 1) out[name] = values;
  }
  return out;
}

function attrsFromSamlProfile(profile: any): Record<string, string | string[]> {
  const out: Record<string, string | string[]> = {};
  if (!profile || typeof profile !== "object") return out;
  const skip = new Set([
    "issuer",
    "inResponseTo",
    "sessionIndex",
    "nameID",
    "nameIDFormat",
    "nameQualifier",
    "spNameQualifier",
  ]);
  for (const [k, v] of Object.entries(profile as Record<string, unknown>)) {
    if (skip.has(k)) continue;
    if (typeof v === "string" && v.trim()) out[k] = v.trim();
    else if (Array.isArray(v) && typeof v[0] === "string") {
      const vals = (v as unknown[]).map((x) => String(x ?? "").trim()).filter(Boolean);
      if (vals.length === 1) out[k] = vals[0]!;
      else if (vals.length > 1) out[k] = vals;
    }
  }
  return out;
}

function pickAttr(attrs: Record<string, string | string[]>, keys: string[]): string {
  for (const k of keys) {
    const direct = attrs[k];
    const v = direct ?? attrs[k.toLowerCase()] ?? attrs[k.toUpperCase()];
    if (typeof v === "string" && v.trim()) return v.trim();
    if (Array.isArray(v) && typeof v[0] === "string" && v[0].trim()) return v[0].trim();
  }
  // fallback: case-insensitive scan
  const lowerKeys = new Set(keys.map((x) => x.toLowerCase()));
  for (const [k, v] of Object.entries(attrs)) {
    if (!lowerKeys.has(k.toLowerCase())) continue;
    if (typeof v === "string" && v.trim()) return v.trim();
    if (Array.isArray(v) && typeof v[0] === "string" && v[0].trim()) return v[0].trim();
  }
  return "";
}

function firstString(v: string | string[]): string {
  if (typeof v === "string") return v;
  if (Array.isArray(v) && typeof v[0] === "string") return v[0];
  return "";
}

function guessEmailFromAttrs(attrs: Record<string, string | string[]>): string {
  // 1) Look for keys that explicitly mention email
  for (const [k, v] of Object.entries(attrs)) {
    if (k.toLowerCase().includes("email")) {
      const s = firstString(v).trim();
      if (s) return s;
    }
    if (k.toLowerCase().endsWith("/emailaddress")) {
      const s = firstString(v).trim();
      if (s) return s;
    }
  }
  // 2) Look for values that look like an email address
  const emailRe = /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i;
  for (const v of Object.values(attrs)) {
    const vals = Array.isArray(v) ? v : [v];
    for (const s0 of vals) {
      const s = String(s0 ?? "").trim();
      if (emailRe.test(s)) return s;
    }
  }
  return "";
}

function escapeHtml(input: string): string {
  return input
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function escapeHtmlAttr(input: string): string {
  // same escaping; kept separate for clarity
  return escapeHtml(input);
}

const AdminTenantSchema = z.object({
  tenantId: z.string().min(1).max(128).regex(/^[a-zA-Z0-9_-]+$/),
  oktaIssuer: z.string().url(),
  clientId: z.string().min(1),
  clientSecret: z.string().min(1),
  scopes: z.string().min(1).optional(),
});

const AdminSamlTenantSchema = z.object({
  tenantId: z.string().min(1).max(128).regex(/^[a-zA-Z0-9_-]+$/),
  idpSsoUrl: z.string().url(),
  idpCert: z.string().min(20),
  idpEntityId: z.string().min(1).optional(),
});

app.get(
  "/admin/login",
  asyncHandler(async (_req, res) => {
    const auth0Enabled = auth0AdminConfigured();
    // If already authed, there's no need to login again.
    // Keep behavior simple: send them to the tenants page.
    // (The tenants page is admin-gated and will render UI.)
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    res.type("html").send(`<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Backupta • Admin login</title>
    <style>
      :root { color-scheme: light dark; --bg:#f8fafc; --panel:#ffffff; --text:#0f172a; --muted:#475569; --border:#e2e8f0; --shadow:0 1px 2px rgba(2,6,23,0.05),0 12px 28px rgba(2,6,23,0.08); --brand:#2563eb; --brand2:#0ea5e9; --radius:14px; }
      @media (prefers-color-scheme: dark){ :root{ --bg:#0b1220; --panel:#0f172a; --text:#e2e8f0; --muted:rgba(226,232,240,0.72); --border:rgba(226,232,240,0.12); --shadow:0 1px 2px rgba(0,0,0,0.35),0 14px 38px rgba(0,0,0,0.45);} }
      *{box-sizing:border-box} body{margin:0;color:var(--text);font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial;font-size:14px;line-height:1.55;}
      .wrap{width:100%;max-width:1440px;margin:22px auto;padding:0 24px 42px;}
      .topbar{display:flex;align-items:center;justify-content:space-between;padding:14px 16px;border:1px solid var(--border);border-radius:var(--radius);background:var(--panel);box-shadow:var(--shadow);backdrop-filter:blur(10px);}
      .brand{display:flex;align-items:center;gap:10px;}
      .logoChip{display:inline-flex;align-items:center;justify-content:center;padding:0;border-radius:12px;}
      .brand-title{display:flex;flex-direction:column;line-height:1.15}
      .brand-title strong{font-size:13px;letter-spacing:0.12em;text-transform:uppercase}
      .brand-title span{font-size:12px;color:var(--muted)}
      .nav{display:flex;gap:8px}
      .pill{display:inline-flex;align-items:center;gap:8px;padding:10px 12px;border-radius:999px;border:1px solid var(--border);background:rgba(127,127,127,0.08);text-decoration:none;font-weight:650;font-size:13px;color:inherit}
      .pill.primary{border-color:rgba(37,99,235,0.25);background:rgba(37,99,235,0.06)}
      .pill.disabled{opacity:0.5;cursor:not-allowed;pointer-events:none}
      .card{margin-top:16px;border:1px solid var(--border);border-radius:var(--radius);background:var(--panel);box-shadow:var(--shadow);padding:18px;backdrop-filter:blur(10px);}
      h1{margin:0 0 6px;font-size:20px;letter-spacing:-0.02em}
      p{margin:0 0 14px;color:var(--muted);font-size:14px;line-height:1.55}
      label{display:grid;gap:6px;font-weight:650;font-size:13px}
      input{padding:11px 12px;border:1px solid var(--border);border-radius:12px;font-size:14px;background:rgba(127,127,127,0.06);color:var(--text);outline:none}
      input:focus{border-color:rgba(99, 91, 255, 0.45);box-shadow:0 0 0 4px rgba(99, 91, 255, 0.12)}
      button{margin-top:12px;padding:11px 14px;border-radius:12px;border:1px solid rgba(37,99,235,0.25);background:var(--brand);color:white;font-weight:750;cursor:pointer;font-size:14px}
      .err{margin-top:12px;padding:12px;border:1px solid rgba(220,38,38,0.6);border-radius:12px;display:none}
    </style>
    <link rel="stylesheet" href="/admin-assets/backupta-pages.css?v=2" />
  </head>
  <body>
    <div class="wrap">
      <div class="topbar">
        <div class="brand">
          <span class="logoChip">
            <img src="/admin-assets/backupta-logo-full-white.png" alt="Backupta" style="height: 18px; width: auto; display:block" />
          </span>
          <div class="brand-title">
            <strong>OIDC Broker Admin</strong>
            <span>Login</span>
          </div>
        </div>
        <div class="nav">
          <a class="pill primary" href="/admin/ui">Add OIDC Integration</a>
          <a class="pill" href="/admin/ui/saml">Add SAML Integration</a>
          <a class="pill" href="/admin/tenants">View tenants</a>
          <a class="pill" href="/admin/login">Admin login</a>
        </div>
      </div>
      <div class="card">
        <h1>Admin login</h1>
        <p>${
          auth0Enabled
            ? "Sign in with Auth0 or enter your admin API key. We’ll store an httpOnly cookie so you don’t need to sign in again on admin pages."
            : "Enter your admin key once. We’ll store an httpOnly cookie so you don’t need to paste it again on admin pages."
        } Workspace labels can include dots (for example <code>acme.prod</code>); to switch workspaces, log out and sign in again with the new label.</p>
        ${
          auth0Enabled
            ? `<a class="pill primary" href="/admin/auth/auth0" style="display:inline-flex;width:100%;max-width:360px;justify-content:center;margin:0 0 10px;text-decoration:none">Continue with Auth0</a>
        <div class="muted" style="font-size:12px;margin:0 0 14px">Authorization Code flow against your Auth0 application.</div>
        <div style="height:1px;background:var(--border);margin:0 0 14px"></div>
        <p class="muted" style="font-size:12px;margin:0 0 10px">Or use admin API key:</p>`
            : ""
        }
        <form id="f">
          <label>Customer / Workspace<input id="c" autocomplete="off" placeholder="acme" value="default" required /></label>
          <label>Admin API key<input id="k" type="password" autocomplete="off" placeholder="Paste ADMIN_API_KEY" required /></label>
          <button type="submit" id="b">Continue</button>
        </form>
        <div class="err" id="err"></div>
      </div>
    </div>
    <script>
      const f = document.getElementById('f');
      const err = document.getElementById('err');
      const b = document.getElementById('b');
      const ae = new URLSearchParams(window.location.search).get('auth0_error');
      if (ae && err) {
        err.textContent = ae;
        err.style.display = '';
        history.replaceState(null, '', '/admin/login');
      }
      f.addEventListener('submit', async (e) => {
        e.preventDefault();
        b.disabled = true;
        err.style.display = 'none';
        try {
          const res = await fetch('/admin/session', {
            method: 'POST',
            credentials: 'include',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ adminKey: document.getElementById('k').value, customerId: document.getElementById('c').value })
          });
          if (!res.ok) {
            const t = await res.text();
            err.textContent = 'Login failed: ' + t;
            err.style.display = '';
            return;
          }
          window.location.href = '/admin/tenants';
        } finally {
          b.disabled = false;
        }
      });
    </script>
  </body>
</html>`);
  }),
);

app.post(
  "/admin/session",
  asyncHandler(async (req, res) => {
    const body = z.object({ adminKey: z.string().min(1), customerId: z.string().min(1).default("default") }).parse(req.body);
    if (body.adminKey !== env.ADMIN_API_KEY) throw httpError(401, "Unauthorized");

    setAdminCookie(res, body.customerId);
    res.json({ ok: true });
  }),
);

app.post(
  "/admin/logout",
  asyncHandler(async (req, res) => {
    clearAdminCookie(res);
    res.json({ ok: true });
  }),
);

app.get(
  "/admin/auth/auth0",
  asyncHandler(async (req, res) => {
    if (!auth0AdminConfigured()) throw httpError(404, "Auth0 admin login is not configured");
    const redirectUri = resolveAuth0RedirectUri(req);
    const state = randomUrlSafeString(24);
    const nonce = randomUrlSafeString(24);
    const signed = signAuth0OAuthState({ state, nonce, exp: Date.now() + AUTH0_STATE_TTL_MS, redirectUri });
    res.cookie(AUTH0_STATE_COOKIE, signed, {
      httpOnly: true,
      secure: cookieSecure(),
      sameSite: "lax",
      path: "/admin",
      maxAge: AUTH0_STATE_TTL_MS,
    });
    const cfg = getAuth0AdminConfig(redirectUri);
    res.redirect(buildAuth0AuthorizeUrl(cfg, state, nonce));
  }),
);

app.get(
  "/admin/auth/auth0/callback",
  asyncHandler(async (req, res) => {
    const baseLogin = `${env.PUBLIC_BASE_URL.replace(/\/$/, "")}/admin/login`;
    const redirectFail = (msg: string) => {
      res.clearCookie(AUTH0_STATE_COOKIE, { path: "/admin" });
      res.redirect(`${baseLogin}?auth0_error=${encodeURIComponent(msg)}`);
    };
    if (!auth0AdminConfigured()) return redirectFail("Auth0 admin login is not configured");

    const oauthErr = typeof req.query.error === "string" ? req.query.error : "";
    if (oauthErr) {
      const desc = typeof req.query.error_description === "string" ? req.query.error_description : oauthErr;
      return redirectFail(desc || oauthErr);
    }
    const code = typeof req.query.code === "string" ? req.query.code : "";
    const state = typeof req.query.state === "string" ? req.query.state : "";
    if (!code || !state) return redirectFail("Missing authorization code or state");

    const parsed = verifyAuth0OAuthState(req.cookies?.[AUTH0_STATE_COOKIE]);
    res.clearCookie(AUTH0_STATE_COOKIE, { path: "/admin" });
    if (!parsed || parsed.state !== state) {
      return redirectFail("Invalid or expired sign-in session (state). Please try again.");
    }

    const cfg = getAuth0AdminConfig(parsed.redirectUri);
    let id_token: string;
    try {
      ({ id_token } = await exchangeAuth0Code(cfg, code));
    } catch (e: unknown) {
      const m = e instanceof Error ? e.message : String(e);
      return redirectFail(m);
    }
    let payload: import("jose").JWTPayload;
    try {
      payload = await verifyAuth0IdToken(cfg, id_token, parsed.nonce);
    } catch (e: unknown) {
      const m = e instanceof Error ? e.message : String(e);
      return redirectFail(`Token validation failed: ${m}`);
    }

    const email = typeof payload.email === "string" ? payload.email.trim().toLowerCase() : "";
    if (cfg.allowedEmails?.length) {
      if (!email || !cfg.allowedEmails.includes(email)) {
        return redirectFail("Your account is not allowed to access broker admin.");
      }
    } else if (!email) {
      return redirectFail("Auth0 did not return an email claim; cannot verify administrator access.");
    }

    const customerId = workspaceFromAuth0Payload(payload, cfg.workspaceClaim);
    setAdminCookie(res, customerId);
    res.redirect("/admin/tenants");
  }),
);

/**
 * Clears broker admin session. If Auth0 is configured, redirects through Auth0 `/v2/logout`
 * so the next "Continue with Auth0" shows the login prompt again (add return URL to Allowed Logout URLs in Auth0).
 */
app.get(
  "/admin/auth/auth0/logout",
  asyncHandler(async (req, res) => {
    clearAdminCookie(res);
    res.clearCookie(AUTH0_STATE_COOKIE, { path: "/admin" });
    const loginUrl = resolveAdminLoginUrl(req);
    if (!auth0AdminConfigured()) {
      res.redirect(loginUrl);
      return;
    }
    const issuer = auth0IssuerFromDomain(env.AUTH0_DOMAIN!);
    const u = new URL("v2/logout", issuer);
    u.searchParams.set("client_id", env.AUTH0_CLIENT_ID!);
    u.searchParams.set("returnTo", loginUrl);
    res.redirect(u.toString());
  }),
);

app.post(
  "/admin/okta/provision",
  asyncHandler(async (req, res) => {
    requireAdmin(req);
    const customerId = getAdminCustomerId(req) ?? "default";

    const body = z
      .object({
        tenantId: z.string().min(1).max(128).regex(/^[a-zA-Z0-9_-]+$/),
        oktaOrgUrl: z.string().min(3),
        sswsToken: z.string().min(10),
        scopes: z.string().min(1).default("openid profile email"),
      })
      .transform((v) => ({
        ...v,
        oktaOrgUrl: v.oktaOrgUrl.includes("://") ? v.oktaOrgUrl : `https://${v.oktaOrgUrl}`,
      }))
      .parse(req.body);

    const inputUrl = new URL(body.oktaOrgUrl);
    let orgHost = inputUrl.host;
    // Okta Admin Console domains often look like "<org>-admin.okta.com".
    orgHost = orgHost.replace("-admin.okta.com", ".okta.com").replace("-admin.oktapreview.com", ".oktapreview.com");
    const org = `${inputUrl.protocol}//${orgHost}`;
    const oktaIssuer = `${org}/oauth2/default`;
    const redirectUri = `${env.PUBLIC_BASE_URL.replace(/\/$/, "")}/oidc/callback`;
    const appLabel = `Backupta OIDC Broker (${body.tenantId})`;

    const headers = {
      accept: "application/json",
      "content-type": "application/json",
      authorization: `SSWS ${body.sswsToken}`,
    };

    // 1) Create OIDC Web app
    const createRes = await fetch(`${org}/api/v1/apps`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        name: "oidc_client",
        label: appLabel,
        signOnMode: "OPENID_CONNECT",
        credentials: {
          oauthClient: {
            token_endpoint_auth_method: "client_secret_basic",
          },
        },
        profile: {
          label: appLabel,
        },
        settings: {
          oauthClient: {
            application_type: "web",
            redirect_uris: [redirectUri],
            response_types: ["code"],
            grant_types: ["authorization_code"],
            // Optional but commonly present in Okta app definitions
            consent_method: "TRUSTED",
          },
        },
      }),
    });
    const createText = await createRes.text().catch(() => "");
    const created = (() => {
      try {
        return JSON.parse(createText);
      } catch {
        return {};
      }
    })() as any;
    if (!createRes.ok) {
      const details =
        typeof created?.errorSummary === "string"
          ? created.errorSummary
          : typeof createText === "string" && createText.length
            ? createText.slice(0, 2000)
            : "Unknown error";
      res.status(400).json({
        error: `Okta app create failed (${createRes.status})`,
        oktaError: details,
        hint:
          inputUrl.host.includes("-admin.")
            ? "You provided an -admin Okta domain; the broker auto-normalized it. If this still fails, try using your org base domain (e.g. https://your-org.okta.com)."
            : "Ensure the SSWS token is valid and has permissions to create apps, and that you used your org base domain (e.g. https://your-org.okta.com).",
        orgUsed: org,
        redirectUri,
      });
      return;
    }

    const appId = String(created?.id ?? "");
    const clientId = String(created?.credentials?.oauthClient?.client_id ?? "");
    const clientSecret = String(created?.credentials?.oauthClient?.client_secret ?? "");
    if (!appId || !clientId || !clientSecret) {
      throw httpError(500, "Okta app created but missing appId/clientId/clientSecret");
    }

    // 2) Find Everyone group
    const groupsRes = await fetch(`${org}/api/v1/groups?q=Everyone&limit=200`, { headers: { accept: "application/json", authorization: `SSWS ${body.sswsToken}` } });
    const groups = (await groupsRes.json().catch(() => [])) as any[];
    if (!groupsRes.ok || !Array.isArray(groups)) throw httpError(400, "Failed to list Okta groups");
    const everyone = groups.find((g) => String(g?.profile?.name ?? "") === "Everyone") ?? groups[0];
    const groupId = String(everyone?.id ?? "");
    if (!groupId) throw httpError(400, "Could not find Everyone group");

    // 3) Assign app to Everyone
    const assignRes = await fetch(`${org}/api/v1/apps/${encodeURIComponent(appId)}/groups/${encodeURIComponent(groupId)}`, {
      method: "PUT",
      headers: { accept: "application/json", authorization: `SSWS ${body.sswsToken}` },
    });
    if (!assignRes.ok) {
      // App exists; still allow continuing but report assignment error.
      // Okta sometimes returns 204 on success.
      const txt = await assignRes.text().catch(() => "");
      throw httpError(400, `App assignment failed (${assignRes.status}) ${txt}`);
    }

    // 4) Upsert into broker tenant config
    const clientSecretEnc = encryptAes256Gcm(clientSecret, aesKey);
    await prisma.tenantOidcConfig.upsert({
      where: { tenantId: body.tenantId },
      create: {
        tenantId: body.tenantId,
        customerId,
        oktaIssuer,
        clientId,
        clientSecretEnc,
        scopes: body.scopes,
      },
      update: {
        customerId,
        oktaIssuer,
        clientId,
        clientSecretEnc,
        scopes: body.scopes,
      },
    });

    res.json({
      tenantId: body.tenantId,
      oktaIssuer,
      clientId,
      clientSecret,
      redirectUri,
      appId,
      assignedGroupId: groupId,
    });
  }),
);

app.post(
  "/admin/okta/provision-saml",
  asyncHandler(async (req, res) => {
    requireAdmin(req);
    const customerId = getAdminCustomerId(req) ?? "default";

    const body = z
      .object({
        tenantId: z.string().min(1).max(128).regex(/^[a-zA-Z0-9_-]+$/),
        oktaOrgUrl: z.string().min(3),
        sswsToken: z.string().min(10),
      })
      .parse(req.body);

    const org = normalizeOktaOrgUrl(body.oktaOrgUrl);
    const appLabel = `Backupta SAML Broker (${body.tenantId})`;
    const acsUrl = samlAcsUrl();
    const spEntityId = samlSpEntityId(body.tenantId);

    const headers = {
      accept: "application/json",
      "content-type": "application/json",
      authorization: `SSWS ${body.sswsToken}`,
    };

    const createRes = await fetch(`${org}/api/v1/apps`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        label: appLabel,
        signOnMode: "SAML_2_0",
        settings: {
          signOn: {
            ssoAcsUrl: acsUrl,
            recipient: acsUrl,
            destination: acsUrl,
            audience: spEntityId,
            subjectNameIdTemplate: "${user.email}",
            subjectNameIdFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            responseSigned: true,
            assertionSigned: true,
            signatureAlgorithm: "RSA_SHA256",
            digestAlgorithm: "SHA256",
            honorForceAuthn: true,
            authnContextClassRef: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
            attributeStatements: [],
          },
        },
        visibility: { autoSubmitToolbar: false, hide: { iOS: true, web: false } },
      }),
    });
    const createText = await createRes.text().catch(() => "");
    const created = (() => {
      try {
        return JSON.parse(createText);
      } catch {
        return {};
      }
    })() as any;

    if (!createRes.ok) {
      const details =
        typeof created?.errorSummary === "string"
          ? created.errorSummary
          : typeof createText === "string" && createText.length
            ? createText.slice(0, 2000)
            : "Unknown error";
      res.status(400).json({
        error: `Okta SAML app create failed (${createRes.status})`,
        oktaError: details,
        orgUsed: org,
        acsUrl,
        spEntityId,
      });
      return;
    }

    const appId = String(created?.id ?? "");
    if (!appId) throw httpError(500, "Okta SAML app created but missing appId");

    // Assign to Everyone (demo-friendly)
    const groupsRes = await fetch(`${org}/api/v1/groups?q=Everyone&limit=200`, {
      headers: { accept: "application/json", authorization: `SSWS ${body.sswsToken}` },
    });
    const groups = (await groupsRes.json().catch(() => [])) as any[];
    if (!groupsRes.ok || !Array.isArray(groups)) throw httpError(400, "Failed to list Okta groups");
    const everyone = groups.find((g) => String(g?.profile?.name ?? "") === "Everyone") ?? groups[0];
    const groupId = String(everyone?.id ?? "");
    if (!groupId) throw httpError(400, "Could not find Everyone group");
    await fetch(`${org}/api/v1/apps/${encodeURIComponent(appId)}/groups/${encodeURIComponent(groupId)}`, {
      method: "PUT",
      headers: { accept: "application/json", authorization: `SSWS ${body.sswsToken}` },
    }).catch(() => {});

    // Fetch metadata link and parse IdP data
    const getRes = await fetch(`${org}/api/v1/apps/${encodeURIComponent(appId)}`, {
      headers: { accept: "application/json", authorization: `SSWS ${body.sswsToken}` },
    });
    const app = (await getRes.json().catch(() => ({}))) as any;
    const metadataUrl = String(app?._links?.metadata?.href ?? "");
    if (!metadataUrl) throw httpError(500, "Okta app missing metadata link");
    const metaRes = await fetch(metadataUrl, { headers: { accept: "application/xml", authorization: `SSWS ${body.sswsToken}` } });
    const metaXml = await metaRes.text().catch(() => "");
    if (!metaRes.ok) throw httpError(400, `Failed to fetch Okta metadata (${metaRes.status})`);

    const { idpSsoUrl, idpCert, idpEntityId } = await extractOktaIdpFromMetadata(metaXml);

    await prisma.tenantSamlConfig.upsert({
      where: { tenantId: body.tenantId },
      create: {
        tenantId: body.tenantId,
        customerId,
        idpSsoUrl,
        idpCert,
        idpEntityId: idpEntityId ?? null,
        oktaOrgUrl: org,
        oktaAppId: appId,
      },
      update: {
        customerId,
        idpSsoUrl,
        idpCert,
        idpEntityId: idpEntityId ?? null,
        oktaOrgUrl: org,
        oktaAppId: appId,
      },
    });

    res.json({
      tenantId: body.tenantId,
      oktaOrgUrl: org,
      oktaAppId: appId,
      metadataUrl,
      acsUrl,
      spEntityId,
      idpSsoUrl,
      idpEntityId: idpEntityId ?? null,
      idpCert,
      assignedGroupId: groupId,
    });
  }),
);

app.post(
  "/admin/okta/delete-saml",
  asyncHandler(async (req, res) => {
    requireAdmin(req);
    const body = z
      .object({
        tenantId: z.string().min(1).max(128).regex(/^[a-zA-Z0-9_-]+$/),
        oktaOrgUrl: z.string().min(3),
        sswsToken: z.string().min(10),
        oktaAppId: z.string().min(5).optional(),
      })
      .parse(req.body);

    const org = normalizeOktaOrgUrl(body.oktaOrgUrl);
    const cfg = await prisma.tenantSamlConfig.findUnique({ where: { tenantId: body.tenantId } });
    const appId = body.oktaAppId ?? (cfg?.oktaAppId ?? "");
    if (!appId) throw httpError(400, "Missing oktaAppId");

    const auth = { accept: "application/json", authorization: `SSWS ${body.sswsToken}` };
    await fetch(`${org}/api/v1/apps/${encodeURIComponent(appId)}/lifecycle/deactivate`, { method: "POST", headers: auth }).catch(() => {});
    const delRes = await fetch(`${org}/api/v1/apps/${encodeURIComponent(appId)}`, { method: "DELETE", headers: auth });
    const txt = await delRes.text().catch(() => "");
    if (!delRes.ok) throw httpError(400, `Okta app delete failed (${delRes.status}) ${txt}`);

    await prisma.tenantSamlConfig
      .update({ where: { tenantId: body.tenantId }, data: { oktaOrgUrl: org, oktaAppId: null } })
      .catch(() => {});

    res.json({ ok: true, tenantId: body.tenantId, oktaOrgUrl: org, oktaAppId: appId });
  }),
);

app.post(
  "/admin/saml/tenants",
  asyncHandler(async (req, res) => {
    requireAdmin(req);
    const customerId = getAdminCustomerId(req) ?? "default";
    const body = AdminSamlTenantSchema.parse(req.body);

    const created = await prisma.tenantSamlConfig.upsert({
      where: { tenantId: body.tenantId },
      create: {
        tenantId: body.tenantId,
        customerId,
        idpSsoUrl: body.idpSsoUrl.replace(/\/$/, ""),
        idpCert: body.idpCert,
        idpEntityId: body.idpEntityId ?? null,
      },
      update: {
        customerId,
        idpSsoUrl: body.idpSsoUrl.replace(/\/$/, ""),
        idpCert: body.idpCert,
        idpEntityId: body.idpEntityId ?? null,
      },
    });

    res.json({
      tenantId: created.tenantId,
      customerId: created.customerId,
      idpSsoUrl: created.idpSsoUrl,
      idpEntityId: created.idpEntityId,
      acsUrl: samlAcsUrl(),
      spEntityId: samlSpEntityId(created.tenantId),
      metadataUrl: `${env.PUBLIC_BASE_URL.replace(/\/$/, "")}/t/${encodeURIComponent(created.tenantId)}/saml/metadata`,
      updatedAt: created.updatedAt,
    });
  }),
);

app.get(
  "/admin/ui",
  asyncHandler(async (_req, res) => {
    const debug = String((_req as any).query?.debug ?? "") === "1";
    if (!debug && !isAdminAuthed(_req)) return res.redirect("/admin/login");
    const adminLogin = debug ? { className: "pill", attrs: 'href="/admin/login"' } : adminLoginHrefOrDisabled(_req);
    res.type("html").send(`<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Backupta • OIDC Broker Admin</title>
    <style>
      :root {
        color-scheme: light dark;
        --bg: #f8fafc;
        --panel: #ffffff;
        --text: #0f172a;
        --muted: #475569;
        --border: #e2e8f0;
        --shadow: 0 1px 2px rgba(2, 6, 23, 0.05), 0 12px 28px rgba(2, 6, 23, 0.08);
        --brand: #2563eb;
        --brand2: #0ea5e9;
        --danger: #dc2626;
        --radius: 14px;
      }
      @media (prefers-color-scheme: dark) {
        :root {
          --bg: #0b1220;
          --panel: rgba(15, 23, 42, 0.6);
          --text: #e2e8f0;
          --muted: rgba(226, 232, 240, 0.72);
          --border: rgba(226, 232, 240, 0.12);
          --shadow: 0 1px 2px rgba(0,0,0,0.35), 0 14px 38px rgba(0,0,0,0.45);
        }
      }
      * { box-sizing: border-box; }
      body {
        margin: 0;
        color: var(--text);
        font-family: Inter, ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial;
        overflow-x: hidden;
      }
      a { color: inherit; }
      .wrap { width: 100%; max-width: 1440px; margin: 22px auto; padding: 0 24px 42px; }
      .topbar {
        display: flex; align-items: center; justify-content: space-between;
        padding: 14px 16px; border: 1px solid var(--border); border-radius: var(--radius);
        background: var(--panel); box-shadow: var(--shadow);
        backdrop-filter: blur(10px);
      }
      .brand { display: flex; align-items: center; gap: 10px; min-width: 0; }
      .logoChip { display: inline-flex; align-items: center; justify-content: center; padding: 0; border-radius: 12px; }
      .brand svg { flex: 0 0 auto; }
      .brand-title { display: flex; flex-direction: column; line-height: 1.15; min-width: 0; }
      .brand-title strong { font-size: 13px; letter-spacing: 0.12em; text-transform: uppercase; }
      .brand-title span { font-size: 12px; color: var(--muted); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
      .nav { display: flex; gap: 8px; }
      .pill {
        display: inline-flex; align-items: center; gap: 8px;
        padding: 10px 12px; border-radius: 999px; border: 1px solid var(--border);
        background: rgba(127,127,127,0.08); text-decoration: none; font-weight: 650; font-size: 13px;
      }
      .pill.primary { border-color: rgba(99, 91, 255, 0.28); background: rgba(99, 91, 255, 0.12); }
      .pill.disabled { opacity: 0.5; cursor: not-allowed; pointer-events: none; }
      .grid { display: grid; grid-template-columns: 1fr; gap: 14px; margin-top: 16px; }
      @media (min-width: 920px) { .grid { grid-template-columns: 1.2fr 0.8fr; } }
      .card {
        border: 1px solid var(--border); border-radius: var(--radius);
        background: var(--panel); box-shadow: var(--shadow);
        padding: 18px; backdrop-filter: blur(10px);
      }
      h1 { margin: 0 0 4px; font-size: 20px; letter-spacing: -0.02em; }
      p { margin: 0 0 14px; color: var(--muted); font-size: 14px; line-height: 1.55; }
      .muted { color: var(--muted); font-size: 12px; }
      form { display: grid; gap: 12px; margin-top: 4px; }
      label { display: grid; gap: 6px; font-weight: 650; font-size: 13px; }
      input {
        padding: 11px 12px;
        border: 1px solid var(--border);
        border-radius: 12px;
        font-size: 14px;
        background: rgba(127,127,127,0.06);
        color: var(--text);
        outline: none;
      }
      input:focus { border-color: rgba(99, 91, 255, 0.45); box-shadow: 0 0 0 4px rgba(99, 91, 255, 0.12); }
      .row { display: grid; grid-template-columns: 1fr; gap: 12px; }
      @media (min-width: 700px) { .row { grid-template-columns: 1fr 1fr; } }
      .btnrow { display: flex; gap: 10px; align-items: center; margin-top: 4px; }
      .fieldtop { display:flex; align-items: baseline; justify-content: space-between; gap: 10px; }
      .linkbtn {
        appearance: none;
        border: 0;
        background: transparent;
        color: var(--muted);
        font-weight: 700;
        cursor: pointer;
        padding: 0;
        font-size: 12px;
        text-decoration: underline;
        text-underline-offset: 3px;
      }
      .linkbtn:hover { color: var(--text); }
      button {
        padding: 11px 14px;
        border-radius: 12px;
        border: 1px solid rgba(37,99,235,0.25);
        background: var(--brand);
        color: white;
        font-weight: 750;
        cursor: pointer;
        font-size: 14px;
      }
      button.secondary {
        background: rgba(127,127,127,0.08);
        color: var(--text);
        border: 1px solid var(--border);
        font-weight: 700;
      }
      button:disabled { opacity: 0.6; cursor: not-allowed; }
      pre {
        margin: 0;
        padding: 12px;
        border-radius: 12px;
        border: 1px solid var(--border);
        overflow: auto;
        background: rgba(2, 6, 23, 0.85);
        color: #e2e8f0;
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
        font-size: 12px;
        line-height: 1.45;
        max-width: 100%;
        white-space: pre-wrap;
        overflow-wrap: anywhere;
        word-break: break-word;
      }
      .kpi { display: grid; gap: 6px; }
      .kpi b { font-size: 13px; }
      .kpi code { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 12px; opacity: 0.92; }
      .callout {
        border: 1px solid var(--border);
        border-radius: 12px;
        padding: 12px;
        background: rgba(37,99,235, 0.06);
      }
      .divider { height: 1px; background: var(--border); margin: 14px 0; }
      .tabs { display: inline-flex; gap: 6px; padding: 4px; border: 1px solid var(--border); border-radius: 999px; background: rgba(127,127,127,0.06); }
      .tabBtn { padding: 9px 12px; border-radius: 999px; border: 1px solid transparent; background: transparent; color: inherit; font-weight: 750; cursor: pointer; font-size: 13px; }
      .tabBtn.active { background: rgba(37,99,235,0.10); border-color: rgba(37,99,235,0.20); }
    </style>
    <link rel="stylesheet" href="/admin-assets/backupta-pages.css?v=2" />
  </head>
  <body>
    <div class="wrap">
      <div class="topbar">
        <div class="brand">
          <span class="logoChip">
            <img src="/admin-assets/backupta-logo-full-white.png" alt="Backupta" style="height: 18px; width: auto; display:block" />
          </span>
          <div class="brand-title">
            <strong>OIDC Broker Admin</strong>
            <span>OIDC Application Integration</span>
          </div>
        </div>
        <div class="nav">
          <a class="pill primary" href="/admin/ui">Add OIDC Integration</a>
          <a class="pill" href="/admin/ui/saml">Add SAML Integration</a>
          <a class="pill" href="/admin/tenants">View tenants</a>
          <a class="${adminLogin.className}" ${adminLogin.attrs}>Admin login</a>
          <a class="pill" href="/admin/auth/auth0/logout" style="opacity:0.9">Logout</a>
        </div>
      </div>

      <div class="grid">
        <div class="card">
          <h1>OIDC Application Integration</h1>
          <p>Create or update a tenant’s OIDC settings for this broker.</p>
          <form id="f" autocomplete="off" onsubmit="return (window.__oidc && window.__oidc.handleSubmit) ? window.__oidc.handleSubmit(event) : true">
            <div class="callout" style="margin-bottom: 4px">
              <div class="kpi">
                <b>Admin auth</b>
                <div class="muted">This page uses your admin cookie. If you aren’t logged in, open <a href="/admin/login">/admin/login</a>.</div>
              </div>
            </div>

            <div class="callout">
              <div class="kpi">
                <b>Okta auto-provision (SSWS)</b>
                <div class="muted">Optional: create the Okta OIDC Web App for this tenant automatically and assign it to the Everyone group.</div>
              </div>
              <div style="height:10px"></div>
              <div class="row">
                <label>
                  Okta org URL
                  <input id="oktaOrgUrl" placeholder="your-org.okta.com" oninput="window.__oidc && window.__oidc.maybeAutofillIssuer && window.__oidc.maybeAutofillIssuer()" onblur="window.__oidc && window.__oidc.normalizeAndAutofill && window.__oidc.normalizeAndAutofill()" />
                </label>
                <label>
                  SSWS API token
                  <input id="oktaSsws" type="password" placeholder="SSWS token" autocomplete="off" />
                </label>
              </div>
              <div class="btnrow" style="margin-top:10px">
                <span class="muted">If provided, provisioning happens automatically on submit. Redirect URI: <code id="redir"></code></span>
              </div>
            </div>

            <div class="divider"></div>
            <div class="row">
              <label>
                Tenant ID
                <input id="tenantId" placeholder="acme" required />
              </label>
              <label>
                Scopes
                <input id="scopes" placeholder="openid profile email" value="openid profile email" />
              </label>
            </div>

            <label>
              Okta issuer
              <input id="oktaIssuer" placeholder="https://your-org.okta.com/oauth2/default" required />
            </label>

            <div class="row">
              <label>
                <div class="fieldtop">
                  <span>Client ID</span>
                  <button class="linkbtn" id="genClientId" type="button" onclick="window.__oidc && window.__oidc.genClientId && window.__oidc.genClientId()">Generate</button>
                </div>
                <input id="clientId" placeholder="0oa..." required />
              </label>
              <label>
                <div class="fieldtop">
                  <span>Client secret</span>
                  <button class="linkbtn" id="genClientSecret" type="button" onclick="window.__oidc && window.__oidc.genClientSecret && window.__oidc.genClientSecret()">Generate</button>
                </div>
                <input id="clientSecret" type="password" placeholder="Paste client secret" autocomplete="off" required />
              </label>
            </div>

            <div class="btnrow">
              <button id="submit" type="submit">Create / update tenant</button>
              <a href="/admin/tenants" style="text-decoration:none"><button class="secondary" type="button">View tenants</button></a>
            </div>
          </form>
          <script>
            // OIDC wiring (ES5 + ASCII only).
            (function () {
              function $(id) { return document.getElementById(id); }
              function val(id) { var el = $(id); return el && el.value != null ? String(el.value) : ''; }
              function setVal(id, v) { var el = $(id); if (el && el.value != null) el.value = String(v); }
              function setOut(msg) { var o = $('out'); if (o) o.textContent = String(msg || ''); }

              function normalizeOktaOrgUrl(raw) {
                try {
                  var v = String(raw || '').trim();
                  if (!v) return null;
                  var withScheme = v.indexOf('://') >= 0 ? v : ('https://' + v);
                  var u = new URL(withScheme);
                  var host = u.host;
                  host = host.replace('-admin.okta.com', '.okta.com').replace('-admin.oktapreview.com', '.oktapreview.com');
                  return u.protocol + '//' + host;
                } catch (e) { return null; }
              }
              function maybeAutofillIssuer() {
                var issuerEl = $('oktaIssuer');
                if (!issuerEl) return;
                var org = normalizeOktaOrgUrl(val('oktaOrgUrl'));
                if (!org) return;
                var base = org;
                if (base.charAt(base.length - 1) === '/') base = base.slice(0, -1);
                var computed = base + '/oauth2/default';
                if (!issuerEl.value || issuerEl.getAttribute('data-autofilled') === 'true') {
                  issuerEl.value = computed;
                  issuerEl.setAttribute('data-autofilled', 'true');
                }
              }
              function normalizeAndAutofill() {
                var orgEl = $('oktaOrgUrl');
                if (!orgEl) return;
                var org = normalizeOktaOrgUrl(val('oktaOrgUrl'));
                if (org) orgEl.value = org;
                maybeAutofillIssuer();
              }

              function randomHex(nBytes) {
                var hex = '0123456789abcdef';
                var out = '';
                var bytes = null;
                try { bytes = new Uint8Array(nBytes); } catch (e) { bytes = null; }
                var c = (window.crypto || window.msCrypto);
                if (bytes && c && c.getRandomValues) {
                  c.getRandomValues(bytes);
                  for (var i = 0; i < bytes.length; i++) {
                    var b = bytes[i] & 255;
                    out += hex[(b >> 4) & 15] + hex[b & 15];
                  }
                  return out;
                }
                // Fallback: Math.random
                for (var j = 0; j < nBytes; j++) {
                  var r = Math.floor(Math.random() * 256);
                  out += hex[(r >> 4) & 15] + hex[r & 15];
                }
                return out;
              }
              function genClientId() { setVal('clientId', 'cid_' + randomHex(12)); }
              function genClientSecret() { setVal('clientSecret', 'sec_' + randomHex(24) + '_' + randomHex(16)); }

              function postJson(url, body, cb) {
                if (!window.fetch) {
                  cb(false, 0, 'fetch() is not available in this browser');
                  return;
                }
                fetch(url, {
                  method: 'POST',
                  credentials: 'include',
                  headers: { 'content-type': 'application/json' },
                  body: JSON.stringify(body),
                }).then(function (res) {
                  return res.text().then(function (text) {
                    cb(!!res.ok, res.status, text);
                  });
                }).catch(function (err) {
                  cb(false, 0, String(err && err.message ? err.message : err));
                });
              }

              function handleSubmit(e) {
                if (e && e.preventDefault) e.preventDefault();
                var submitBtn = $('submit');
                if (submitBtn) submitBtn.disabled = true;
                var tenantId = String(val('tenantId') || '').trim();
                var oktaOrgUrl = String(val('oktaOrgUrl') || '').trim();
                var sswsToken = String(val('oktaSsws') || '');
                var scopes = String(val('scopes') || '').trim();
                if (!tenantId) {
                  setOut('ERROR\\n\\nMissing Tenant ID.');
                  if (submitBtn) submitBtn.disabled = false;
                  return false;
                }
                var shouldProvision = !!oktaOrgUrl || !!sswsToken;
                if (shouldProvision) {
                  if (!oktaOrgUrl) { setOut('ERROR\\n\\nMissing Okta org URL.'); if (submitBtn) submitBtn.disabled = false; return false; }
                  if (!sswsToken) { setOut('ERROR\\n\\nMissing SSWS token.'); if (submitBtn) submitBtn.disabled = false; return false; }
                  setOut('Provisioning Okta app + saving tenant...');
                  postJson('/admin/okta/provision', { tenantId: tenantId, oktaOrgUrl: oktaOrgUrl, sswsToken: sswsToken, scopes: scopes || 'openid profile email' }, function (ok, status, text) {
                    var parsed = text;
                    var data = null;
                    try { data = JSON.parse(text); parsed = JSON.stringify(data, null, 2); } catch (e2) {}
                    setOut((ok ? 'OK\\n\\n' : ('ERROR ' + String(status) + '\\n\\n')) + parsed);
                    if (ok && data) {
                      if (data.oktaIssuer) setVal('oktaIssuer', data.oktaIssuer);
                      if (data.clientId) setVal('clientId', data.clientId);
                      if (data.clientSecret) setVal('clientSecret', data.clientSecret);
                    }
                    if (submitBtn) submitBtn.disabled = false;
                  });
                  return false;
                }
                setOut('Saving tenant...');
                postJson('/admin/tenants', {
                  tenantId: tenantId,
                  oktaIssuer: String(val('oktaIssuer') || '').trim(),
                  clientId: String(val('clientId') || '').trim(),
                  clientSecret: String(val('clientSecret') || ''),
                  scopes: scopes || undefined,
                }, function (ok2, status2, text2) {
                  var parsed2 = text2;
                  try { parsed2 = JSON.stringify(JSON.parse(text2), null, 2); } catch (e3) {}
                  setOut((ok2 ? 'OK\\n\\n' : ('ERROR ' + String(status2) + '\\n\\n')) + parsed2);
                  if (submitBtn) submitBtn.disabled = false;
                });
                return false;
              }

              window.__oidc = {
                maybeAutofillIssuer: maybeAutofillIssuer,
                normalizeAndAutofill: normalizeAndAutofill,
                genClientId: genClientId,
                genClientSecret: genClientSecret,
                handleSubmit: handleSubmit,
              };

              var redirEl = $('redir');
              if (redirEl) redirEl.textContent = window.location.origin + '/oidc/callback';
              normalizeAndAutofill();
              var form = $('f');
              if (form) form.onsubmit = handleSubmit;
            })();
          </script>

        </div>

        <div class="card">
          <h1>Result</h1>
          <p>We’ll show the API response here. No secrets are returned.</p>
          <pre id="out">(no request yet)</pre>
          <div style="height:12px"></div>
          <div class="callout">
            <div class="kpi">
              <b>Tip</b>
              <div class="muted">Start login at:</div>
              <code>/t/&lt;tenantId&gt;/login</code>
            </div>
          </div>
        </div>
      </div>
    </div>
  </body>
</html>`);
  }),
);

app.get(
  "/admin/ui/saml",
  asyncHandler(async (_req, res) => {
    const debug = String((_req as any).query?.debug ?? "") === "1";
    if (!debug && !isAdminAuthed(_req)) return res.redirect("/admin/login");
    const adminLogin = debug ? { className: "pill", attrs: 'href="/admin/login"' } : adminLoginHrefOrDisabled(_req);
    res.type("html").send(`<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Backupta • SAML Broker Admin</title>
    <style>
      :root {
        color-scheme: light dark;
        --bg: #f8fafc;
        --panel: #ffffff;
        --text: #0f172a;
        --muted: #475569;
        --border: #e2e8f0;
        --shadow: 0 1px 2px rgba(2, 6, 23, 0.05), 0 12px 28px rgba(2, 6, 23, 0.08);
        --brand: #2563eb;
        --brand2: #0ea5e9;
        --danger: #dc2626;
        --radius: 14px;
      }
      @media (prefers-color-scheme: dark) {
        :root {
          --bg: #0b1220;
          --panel: rgba(15, 23, 42, 0.6);
          --text: #e2e8f0;
          --muted: rgba(226, 232, 240, 0.72);
          --border: rgba(226, 232, 240, 0.12);
          --shadow: 0 1px 2px rgba(0,0,0,0.35), 0 14px 38px rgba(0,0,0,0.45);
        }
      }
      * { box-sizing: border-box; }
      body {
        margin: 0;
        color: var(--text);
        font-family: Inter, ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial;
        overflow-x: hidden;
      }
      a { color: inherit; }
      .wrap { width: 100%; max-width: 1440px; margin: 22px auto; padding: 0 24px 42px; }
      .topbar {
        display: flex; align-items: center; justify-content: space-between;
        padding: 14px 16px; border: 1px solid var(--border); border-radius: var(--radius);
        background: var(--panel); box-shadow: var(--shadow);
        backdrop-filter: blur(10px);
      }
      .brand { display: flex; align-items: center; gap: 10px; min-width: 0; }
      .logoChip { display: inline-flex; align-items: center; justify-content: center; padding: 0; border-radius: 12px; }
      .brand svg { flex: 0 0 auto; }
      .brand-title { display: flex; flex-direction: column; line-height: 1.15; min-width: 0; }
      .brand-title strong { font-size: 13px; letter-spacing: 0.12em; text-transform: uppercase; }
      .brand-title span { font-size: 12px; color: var(--muted); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
      .nav { display: flex; gap: 8px; flex-wrap: wrap; }
      .pill {
        display: inline-flex; align-items: center; gap: 8px;
        padding: 10px 12px; border-radius: 999px; border: 1px solid var(--border);
        background: rgba(127,127,127,0.08); text-decoration: none; font-weight: 650; font-size: 13px;
      }
      .pill.primary { border-color: rgba(99, 91, 255, 0.28); background: rgba(99, 91, 255, 0.12); }
      .pill.disabled { opacity: 0.5; cursor: not-allowed; pointer-events: none; }
      .grid { display: grid; grid-template-columns: 1fr; gap: 14px; margin-top: 16px; }
      @media (min-width: 920px) { .grid { grid-template-columns: 1.2fr 0.8fr; } }
      .card {
        border: 1px solid var(--border); border-radius: var(--radius);
        background: var(--panel); box-shadow: var(--shadow);
        padding: 18px; backdrop-filter: blur(10px);
      }
      h1 { margin: 0 0 4px; font-size: 20px; letter-spacing: -0.02em; }
      p { margin: 0 0 14px; color: var(--muted); font-size: 14px; line-height: 1.55; }
      .muted { color: var(--muted); font-size: 12px; }
      form { display: grid; gap: 12px; margin-top: 4px; }
      label { display: grid; gap: 6px; font-weight: 650; font-size: 13px; }
      input, textarea {
        padding: 11px 12px;
        border: 1px solid var(--border);
        border-radius: 12px;
        font-size: 14px;
        background: rgba(127,127,127,0.06);
        color: var(--text);
        outline: none;
      }
      textarea { min-height: 120px; font-family: inherit; resize: vertical; }
      input:focus, textarea:focus { border-color: rgba(99, 91, 255, 0.45); box-shadow: 0 0 0 4px rgba(99, 91, 255, 0.12); }
      .row { display: grid; grid-template-columns: 1fr; gap: 12px; }
      @media (min-width: 700px) { .row { grid-template-columns: 1fr 1fr; } }
      .btnrow { display: flex; gap: 10px; align-items: center; margin-top: 4px; }
      button {
        padding: 11px 14px;
        border-radius: 12px;
        border: 1px solid rgba(37,99,235,0.25);
        background: var(--brand);
        color: white;
        font-weight: 750;
        cursor: pointer;
        font-size: 14px;
      }
      button.secondary {
        background: rgba(127,127,127,0.08);
        color: var(--text);
        border: 1px solid var(--border);
        font-weight: 700;
      }
      button:disabled { opacity: 0.6; cursor: not-allowed; }
      pre {
        margin: 0;
        padding: 12px;
        border-radius: 12px;
        border: 1px solid var(--border);
        overflow: auto;
        background: rgba(2, 6, 23, 0.85);
        color: #e2e8f0;
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
        font-size: 12px;
        line-height: 1.45;
        max-width: 100%;
        white-space: pre-wrap;
        overflow-wrap: anywhere;
        word-break: break-word;
      }
      .kpi { display: grid; gap: 6px; }
      .kpi b { font-size: 13px; }
      .kpi code { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 12px; opacity: 0.92; }
      .callout {
        border: 1px solid var(--border);
        border-radius: 12px;
        padding: 12px;
        background: rgba(37,99,235, 0.06);
      }
    </style>
    <link rel="stylesheet" href="/admin-assets/backupta-pages.css?v=2" />
  </head>
  <body>
    <div class="wrap">
      <div class="topbar">
        <div class="brand">
          <span class="logoChip">
            <img src="/admin-assets/backupta-logo-full-white.png" alt="Backupta" style="height: 18px; width: auto; display:block" />
          </span>
          <div class="brand-title">
            <strong>SAML Broker Admin</strong>
            <span>SAML Application Integration</span>
          </div>
        </div>
        <div class="nav">
          <a class="pill" href="/admin/ui">Add OIDC Integration</a>
          <a class="pill primary" href="/admin/ui/saml">Add SAML Integration</a>
          <a class="pill" href="/admin/tenants">View tenants</a>
          <a class="${adminLogin.className}" ${adminLogin.attrs}>Admin login</a>
          <a class="pill" href="/admin/auth/auth0/logout" style="opacity:0.9">Logout</a>
        </div>
      </div>

      <div class="grid">
        <div class="card">
          <h1>SAML Application Integration</h1>
          <p>Configure SAML (SP-initiated). This flow is independent of OIDC.</p>
          <div class="callout" style="margin-bottom: 12px">
            <div class="kpi">
              <b>Admin auth</b>
              <div class="muted">This page uses your admin cookie. If you aren’t logged in, open <a href="/admin/login">/admin/login</a>.</div>
            </div>
          </div>

          <form id="samlForm" autocomplete="off">
            <div class="callout" style="margin-bottom: 12px">
              <div class="kpi">
                <b>Okta auto-provision (SSWS)</b>
                <div class="muted">Optional: create/delete the Okta SAML app and auto-fill IdP SSO URL + cert.</div>
              </div>
              <div style="height:12px"></div>
              <div class="kpi" style="margin-bottom:8px">
                <b>Tenant ID</b>
                <div class="muted">Used for the SAML app name and metadata paths.</div>
              </div>
              <label>
                <input id="samlTenantId" placeholder="acme" required aria-label="Tenant ID" />
              </label>
              <div style="height:14px"></div>
              <div class="kpi" style="margin-bottom:8px">
                <b>IdP Entity ID</b>
                <div class="muted">Optional. Okta may fill this after Create Okta SAML app; you can also set it before saving the tenant.</div>
              </div>
              <label>
                <input id="samlIdpEntityId" placeholder="http://www.okta.com/exk..." aria-label="IdP Entity ID (optional)" />
              </label>
              <div style="height:1px;background:var(--border);margin:14px 0"></div>
              <div class="kpi" style="margin-bottom:8px">
                <b>Okta org and API token</b>
                <div class="muted">SSWS credentials for create/delete app API calls.</div>
              </div>
              <div class="row">
                <label>
                  Okta org URL
                  <input id="samlOktaOrgUrl" placeholder="your-org.okta.com" />
                </label>
                <label>
                  SSWS API token
                  <input id="samlOktaSsws" type="password" placeholder="SSWS token" autocomplete="off" />
                </label>
              </div>
              <div class="btnrow" style="margin-top:10px; gap: 10px; flex-wrap: wrap">
                <button class="secondary" id="samlProvisionBtn" type="button">Create Okta SAML app</button>
                <button class="secondary" id="samlDeleteBtn" type="button">Delete Okta SAML app</button>
                <span class="muted">Entity ID: <code id="samlSpEntity"></code></span>
              </div>
            </div>

            <div class="callout" style="margin-bottom: 10px">
              <div class="kpi">
                <b>Service Provider metadata</b>
                <div class="muted">Give your IdP this metadata URL:</div>
                <code id="samlMetadata"></code>
              </div>
              <div style="height:8px"></div>
              <div class="muted">ACS URL: <code id="samlAcs"></code></div>
              <div class="muted" style="margin-top:6px">Start login at: <code id="samlLoginUrl"></code></div>
            </div>

            <label>
              IdP SSO URL
              <input id="samlIdpSsoUrl" placeholder="https://your-org.okta.com/app/.../sso/saml" required />
            </label>
            <label>
              IdP signing certificate
              <textarea id="samlIdpCert" spellcheck="false" placeholder="Paste the X.509 cert (PEM or base64)" required></textarea>
            </label>
            <div class="btnrow" style="margin-top:12px">
              <button id="samlSubmit" type="submit">Create / update SAML tenant</button>
            </div>
          </form>

          <script>
            (function () {
              function $(id) { return document.getElementById(id); }
              function setOut(msg) { var o = document.getElementById('out'); if (o) o.textContent = String(msg || ''); }
              function normOrg(raw) {
                try {
                  var v = String(raw || '').trim();
                  if (!v) return '';
                  var withScheme = v.indexOf('://') >= 0 ? v : ('https://' + v);
                  var u = new URL(withScheme);
                  var host = u.host;
                  host = host.replace('-admin.okta.com', '.okta.com').replace('-admin.oktapreview.com', '.oktapreview.com');
                  return u.protocol + '//' + host;
                } catch (e) { return ''; }
              }
              function updateDerived() {
                var tidEl = $('samlTenantId');
                var tid = tidEl && 'value' in tidEl ? String(tidEl.value || '').trim() : '';
                var metaUrl = window.location.origin + '/t/' + encodeURIComponent(tid || '<tenantId>') + '/saml/metadata';
                var loginUrl = window.location.origin + '/t/' + encodeURIComponent(tid || '<tenantId>') + '/saml/login';
                var meta = $('samlMetadata'); if (meta) meta.textContent = metaUrl;
                var ent = $('samlSpEntity'); if (ent) ent.textContent = metaUrl;
                var login = $('samlLoginUrl'); if (login) login.textContent = loginUrl;
                var acs = $('samlAcs'); if (acs) acs.textContent = window.location.origin + '/saml/acs';
              }
              var tidEl = $('samlTenantId');
              if (tidEl) tidEl.addEventListener('input', updateDerived);
              updateDerived();

              var orgEl = $('samlOktaOrgUrl');
              if (orgEl) {
                orgEl.addEventListener('blur', function () {
                  var n = normOrg(String(orgEl.value || '').trim());
                  if (n) orgEl.value = n;
                });
              }

              function postJson(url, body, cb) {
                fetch(url, { method: 'POST', credentials: 'include', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })
                  .then(function (res) { return res.text().then(function (t) { cb(res.ok, res.status, t); }); })
                  .catch(function (e) { cb(false, 0, String(e && e.message ? e.message : e)); });
              }

              var provisionBtn = $('samlProvisionBtn');
              if (provisionBtn) provisionBtn.addEventListener('click', function () {
                var tenantId = String(($('samlTenantId') && $('samlTenantId').value) || '').trim();
                var oktaOrgUrl = String(($('samlOktaOrgUrl') && $('samlOktaOrgUrl').value) || '').trim();
                var sswsToken = String(($('samlOktaSsws') && $('samlOktaSsws').value) || '');
                if (!tenantId) return setOut('ERROR\\n\\nMissing tenantId.');
                if (!oktaOrgUrl) return setOut('ERROR\\n\\nMissing Okta org URL.');
                if (!sswsToken) return setOut('ERROR\\n\\nMissing SSWS token.');
                setOut('Provisioning Okta SAML app + saving tenant...');
                postJson('/admin/okta/provision-saml', { tenantId: tenantId, oktaOrgUrl: oktaOrgUrl, sswsToken: sswsToken }, function (ok, status, text) {
                  var parsed = text; var data = null;
                  try { data = JSON.parse(text); parsed = JSON.stringify(data, null, 2); } catch (e) {}
                  if (ok && data) {
                    if (data.idpSsoUrl) $('samlIdpSsoUrl').value = data.idpSsoUrl;
                    if (data.idpCert) $('samlIdpCert').value = data.idpCert;
                    if (data.idpEntityId) $('samlIdpEntityId').value = data.idpEntityId;
                  }
                  setOut((ok ? 'OK\\n\\n' : ('ERROR ' + String(status) + '\\n\\n')) + parsed);
                });
              });

              var deleteBtn = $('samlDeleteBtn');
              if (deleteBtn) deleteBtn.addEventListener('click', function () {
                var tenantId = String(($('samlTenantId') && $('samlTenantId').value) || '').trim();
                var oktaOrgUrl = String(($('samlOktaOrgUrl') && $('samlOktaOrgUrl').value) || '').trim();
                var sswsToken = String(($('samlOktaSsws') && $('samlOktaSsws').value) || '');
                if (!tenantId) return setOut('ERROR\\n\\nMissing tenantId.');
                if (!oktaOrgUrl) return setOut('ERROR\\n\\nMissing Okta org URL.');
                if (!sswsToken) return setOut('ERROR\\n\\nMissing SSWS token.');
                setOut('Deleting Okta SAML app...');
                postJson('/admin/okta/delete-saml', { tenantId: tenantId, oktaOrgUrl: oktaOrgUrl, sswsToken: sswsToken }, function (ok, status, text) {
                  var parsed = text;
                  try { parsed = JSON.stringify(JSON.parse(text), null, 2); } catch (e) {}
                  setOut((ok ? 'OK\\n\\n' : ('ERROR ' + String(status) + '\\n\\n')) + parsed);
                });
              });

              var form = $('samlForm');
              if (form) form.addEventListener('submit', function (e) {
                e.preventDefault();
                var tenantId = String(($('samlTenantId') && $('samlTenantId').value) || '').trim();
                if (!tenantId) return setOut('ERROR\\n\\nMissing tenantId.');
                setOut('Saving SAML tenant...');
                postJson('/admin/saml/tenants', {
                  tenantId: tenantId,
                  idpSsoUrl: String(($('samlIdpSsoUrl') && $('samlIdpSsoUrl').value) || '').trim(),
                  idpCert: String(($('samlIdpCert') && $('samlIdpCert').value) || ''),
                  idpEntityId: String(($('samlIdpEntityId') && $('samlIdpEntityId').value) || '').trim() || undefined,
                }, function (ok, status, text) {
                  var parsed = text;
                  try { parsed = JSON.stringify(JSON.parse(text), null, 2); } catch (e2) {}
                  setOut((ok ? 'OK\\n\\n' : ('ERROR ' + String(status) + '\\n\\n')) + parsed);
                });
              });
            })();
          </script>
        </div>

        <div class="card">
          <h1>Result</h1>
          <p>We’ll show the API response here. No secrets are returned.</p>
          <pre id="out">(no request yet)</pre>
          <div style="height:12px"></div>
          <div class="callout">
            <div class="kpi">
              <b>Tip</b>
              <div class="muted">Start SAML login at:</div>
              <code>/t/&lt;tenantId&gt;/saml/login</code>
            </div>
          </div>
        </div>
      </div>
    </div>
  </body>
</html>`);
  }),
);

app.get(
  "/admin/tenants",
  asyncHandler(async (req, res) => {
    const key = req.header("x-admin-key");
    const wantsJson =
      req.query.format === "json" ||
      String(req.header("accept") ?? "").includes("application/json") ||
      (String(req.header("accept") ?? "").includes("*/*") && req.header("x-admin-key") != null);

    const adminCustomerId = getAdminCustomerId(req);
    if (wantsJson && ((key && key === env.ADMIN_API_KEY) || adminCustomerId)) {
      const where =
        key && key === env.ADMIN_API_KEY ? undefined : { customerId: adminCustomerId ?? "default" as string };

      const [oidcTenants, samlTenants] = await Promise.all([
        prisma.tenantOidcConfig.findMany({
          where,
          select: {
            tenantId: true,
            customerId: true,
            oktaIssuer: true,
            clientId: true,
            scopes: true,
            createdAt: true,
            updatedAt: true,
          },
        }),
        prisma.tenantSamlConfig.findMany({
          where,
          select: {
            tenantId: true,
            customerId: true,
            idpSsoUrl: true,
            idpEntityId: true,
            oktaOrgUrl: true,
            oktaAppId: true,
            createdAt: true,
            updatedAt: true,
          },
        }),
      ]);

      const tenants = [
        ...oidcTenants.map((t) => ({
          protocol: "oidc" as const,
          tenantId: t.tenantId,
          customerId: t.customerId,
          primary: t.oktaIssuer,
          secondary: t.clientId,
          updatedAt: t.updatedAt,
          loginUrl: `/t/${encodeURIComponent(t.tenantId)}/login`,
          details: { scopes: t.scopes },
        })),
        ...samlTenants.map((t) => ({
          protocol: "saml" as const,
          tenantId: t.tenantId,
          customerId: t.customerId,
          primary: t.idpSsoUrl,
          secondary: t.oktaAppId ?? "",
          updatedAt: t.updatedAt,
          loginUrl: `/t/${encodeURIComponent(t.tenantId)}/saml/login`,
          details: { idpEntityId: t.idpEntityId ?? null, oktaOrgUrl: t.oktaOrgUrl ?? null },
        })),
      ].sort((a, b) => new Date(b.updatedAt).getTime() - new Date(a.updatedAt).getTime());

      return res.json({ tenants });
    }
    if (wantsJson) throw httpError(401, "Unauthorized");
    if (!isAdminAuthed(req)) return res.redirect("/admin/login");
    const adminLogin = adminLoginHrefOrDisabled(req);
    const workspace = getAdminCustomerId(req) ?? "default";

    // Browser page that can fetch the JSON list by providing the admin key.
    res.type("html").send(`<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Backupta • Configured Tenants</title>
    <style>
      :root {
        color-scheme: light dark;
        --bg: #f8fafc;
        --panel: #ffffff;
        --text: #0f172a;
        --muted: #475569;
        --border: #e2e8f0;
        --shadow: 0 1px 2px rgba(2, 6, 23, 0.05), 0 12px 28px rgba(2, 6, 23, 0.08);
        --brand: #2563eb;
        --brand2: #0ea5e9;
        --brand-purple: #635bff;
        --danger: #dc2626;
        --radius: 14px;
      }
      @media (prefers-color-scheme: dark) {
        :root {
          --bg: #0b1220;
          --panel: rgba(15, 23, 42, 0.6);
          --text: #e2e8f0;
          --muted: rgba(226, 232, 240, 0.72);
          --border: rgba(226, 232, 240, 0.12);
          --shadow: 0 1px 2px rgba(0,0,0,0.35), 0 14px 38px rgba(0,0,0,0.45);
        }
      }
      * { box-sizing: border-box; }
      body {
        margin: 0;
        color: var(--text);
        font-family: Inter, ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial;
      }
      .wrap { width: 100%; max-width: 1440px; margin: 22px auto; padding: 0 24px 42px; }
      .topbar {
        display: flex; align-items: center; justify-content: space-between;
        padding: 14px 16px; border: 1px solid var(--border); border-radius: var(--radius);
        background: var(--panel); box-shadow: var(--shadow);
        backdrop-filter: blur(10px);
      }
      .brand { display: flex; align-items: center; gap: 10px; min-width: 0; }
      .logoChip { display: inline-flex; align-items: center; justify-content: center; padding: 0; border-radius: 12px; }
      .brand-title { display: flex; flex-direction: column; line-height: 1.15; min-width: 0; }
      .brand-title strong { font-size: 13px; letter-spacing: 0.12em; text-transform: uppercase; }
      .brand-title span { font-size: 12px; color: var(--muted); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
      .nav { display: flex; gap: 8px; }
      .pill {
        display: inline-flex; align-items: center; gap: 8px;
        padding: 10px 12px; border-radius: 999px; border: 1px solid var(--border);
        background: rgba(127,127,127,0.08); text-decoration: none; font-weight: 650; font-size: 13px;
      }
      .pill.primary { border-color: rgba(99, 91, 255, 0.28); background: rgba(99, 91, 255, 0.12); }
      .pill.disabled { opacity: 0.5; cursor: not-allowed; pointer-events: none; }
      .card {
        margin-top: 16px;
        border: 1px solid var(--border); border-radius: var(--radius);
        background: var(--panel); box-shadow: var(--shadow);
        padding: 18px; backdrop-filter: blur(10px);
      }
      h1 { margin: 0 0 6px; font-size: 20px; letter-spacing: -0.02em; }
      p { margin: 0 0 14px; color: var(--muted); font-size: 14px; line-height: 1.55; }
      .row { display: grid; grid-template-columns: 1fr; gap: 10px; align-items: end; max-width: 840px; }
      @media (min-width: 760px) { .row { grid-template-columns: 1fr auto auto; } }
      label { display: grid; gap: 6px; font-weight: 650; font-size: 13px; }
      input {
        padding: 11px 12px;
        border: 1px solid var(--border);
        border-radius: 12px;
        font-size: 14px;
        background: rgba(127,127,127,0.06);
        color: var(--text);
        outline: none;
      }
      input:focus { border-color: rgba(99, 91, 255, 0.45); box-shadow: 0 0 0 4px rgba(99, 91, 255, 0.12); }
      button {
        padding: 11px 14px;
        border-radius: 12px;
        border: 1px solid rgba(37,99,235,0.25);
        background: var(--brand);
        color: white;
        font-weight: 750;
        cursor: pointer;
        font-size: 14px;
      }
      button.secondary {
        background: rgba(127,127,127,0.08);
        color: var(--text);
        border: 1px solid var(--border);
        font-weight: 700;
      }
      button:disabled { opacity: 0.6; cursor: not-allowed; }
      .actionBtn {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        padding: 9px 14px;
        border-radius: 10px;
        border: 1px solid rgba(37,99,235,0.25);
        background: var(--brand);
        color: white;
        font-weight: 750;
        font-size: 14px;
        text-decoration: none;
        white-space: nowrap;
      }
      .actionBtn:hover { filter: brightness(0.97); }
      .actionBtn:active { transform: translateY(0.5px); }
      .actionBtn.oidc {
        border-color: rgba(99,91,255,0.35);
        background: linear-gradient(135deg, var(--brand-purple), var(--brand) 48%, var(--brand2));
      }
      .actionBtn.saml {
        border-color: rgba(14,165,233,0.35);
        background: linear-gradient(135deg, rgba(14,165,233,0.18), rgba(37,99,235,0.08));
        color: var(--text);
      }
      .tableWrap { margin-top: 14px; overflow-x: auto; border-radius: 12px; border: 1px solid var(--border); }
      table { width: 100%; border-collapse: collapse; min-width: 860px; background: var(--panel); table-layout: fixed; }
      th, td { text-align: left; padding: 12px 10px; border-bottom: 1px solid var(--border); vertical-align: middle; }
      th { font-size: 12px; text-transform: uppercase; letter-spacing: 0.08em; color: var(--muted); }
      thead th { background: rgba(127,127,127,0.06); }
      tbody tr:last-child td { border-bottom: 0; }
      code { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 12px; }
      td { min-width: 0; }
      td.primary code {
        display: block;
        white-space: nowrap;
        overflow-x: auto;
        overflow-y: hidden;
        text-overflow: clip;
        max-width: 100%;
      }
      /* Let issuer/SSO use available width; scroll inside cell if needed */
      th.colTenant { width: 150px; }
      th.colProto { width: 110px; }
      th.colApp { width: 240px; }
      th.colUpdated { width: 170px; }
      th.colActions { width: 150px; }
      td.actions { white-space: nowrap; }
      td.updated { white-space: nowrap; }
      .proto {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        padding: 6px 10px;
        border-radius: 999px;
        border: 1px solid var(--border);
        background: rgba(127,127,127,0.06);
        font-weight: 800;
        font-size: 12px;
        text-transform: uppercase;
        letter-spacing: 0.08em;
      }
      .proto.oidc {
        border-color: rgba(99,91,255,0.26);
        background: linear-gradient(135deg, rgba(99,91,255,0.14), rgba(37,99,235,0.07), rgba(14,165,233,0.12));
        color: inherit;
      }
      .proto.saml { border-color: rgba(14,165,233,0.22); background: rgba(14,165,233,0.08); color: inherit; }
      .dot { width: 8px; height: 8px; border-radius: 999px; display: inline-block; }
      .dot.oidc { background: linear-gradient(135deg, var(--brand-purple), var(--brand) 45%, var(--brand2)); }
      .dot.saml { background: rgba(14,165,233,1); }
      .muted { color: var(--muted); font-size: 12px; }
      .error { margin-top: 12px; padding: 12px; border: 1px solid rgba(220,38,38,0.6); border-radius: 12px; }
      .empty { margin-top: 12px; color: var(--muted); }
      .filters { margin-top: 10px; display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
      .filters .spacer { flex: 1; }
      .hint { color: var(--muted); font-size: 12px; }
      a { color: inherit; }
    </style>
    <link rel="stylesheet" href="/admin-assets/backupta-pages.css?v=2" />
  </head>
  <body>
    <div class="wrap">
      <div class="topbar">
        <div class="brand">
          <span class="logoChip">
            <img src="/admin-assets/backupta-logo-full-white.png" alt="Backupta" style="height: 18px; width: auto; display:block" />
          </span>
          <div class="brand-title">
            <strong>Configured tenants</strong>
            <span>OIDC Broker Admin</span>
          </div>
        </div>
        <div class="nav">
          <a class="pill" href="/admin/ui">Add OIDC Integration</a>
          <a class="pill" href="/admin/ui/saml">Add SAML Integration</a>
          <a class="pill primary" href="/admin/tenants">View tenants</a>
          <a class="${adminLogin.className}" ${adminLogin.attrs}>Admin login</a>
          <a class="pill" href="/admin/auth/auth0/logout" style="opacity:0.9">Logout</a>
        </div>
      </div>

      <div class="card">
        <h1>Tenants</h1>
        <p>This page shows tenants for workspace <code>${escapeHtml(workspace)}</code>.</p>

        <div class="filters">
          <label style="min-width: 280px; max-width: 420px; width: 100%">
            Search tenants
            <input id="q" autocomplete="off" placeholder="Filter by tenant name (e.g. acme)" />
          </label>
          <div class="spacer"></div>
          <div class="hint">Tip: use this filter during demos to show only the tenants you want.</div>
        </div>

        <div id="msg"></div>
        <div class="tableWrap" id="wrapTbl" style="display:none">
          <table id="tbl">
            <thead>
              <tr>
                <th class="colTenant">Tenant</th>
                <th class="colProto">Protocol</th>
                <th class="primaryCol">Issuer / SSO URL</th>
                <th class="colApp">App identifier</th>
                <th class="colUpdated">Updated</th>
                <th class="colActions">Actions</th>
              </tr>
            </thead>
            <tbody id="tbody"></tbody>
          </table>
        </div>
      </div>
    </div>

    <script>
      const msg = document.getElementById('msg');
      const tbl = document.getElementById('tbl');
      const wrapTbl = document.getElementById('wrapTbl');
      const tbody = document.getElementById('tbody');
      const q = document.getElementById('q');
      let allTenants = [];

      function esc(s) {
        return String(s ?? '').replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
      }

      function fmtDate(v) {
        try {
          const d = new Date(v);
          return new Intl.DateTimeFormat(undefined, { year:'numeric', month:'short', day:'2-digit', hour:'2-digit', minute:'2-digit' }).format(d);
        } catch { return String(v ?? ''); }
      }

      function norm(s) { return String(s ?? '').toLowerCase(); }

      function renderTenants(tenants) {
        tbody.innerHTML = '';
        for (const t of tenants) {
          const tr = document.createElement('tr');
          const loginUrl = t.loginUrl || ('/t/' + encodeURIComponent(t.tenantId) + '/login');
          const proto = String(t.protocol || 'oidc');
          const protoLabel = proto === 'saml' ? 'SAML' : 'OIDC';
          const actionLabel = proto === 'saml' ? 'SAML Login' : 'OIDC Login';
          const primary = t.primary || t.oktaIssuer || '';
          const secondary = t.secondary || t.clientId || '';
          tr.innerHTML = ''
            + '<td><code>' + esc(t.tenantId) + '</code></td>'
            + '<td><span class="proto ' + esc(proto) + '"><span class="dot ' + esc(proto) + '"></span>' + esc(protoLabel) + '</span></td>'
            + '<td class="primary"><code title="' + esc(primary) + '">' + esc(primary) + '</code></td>'
            + '<td><code>' + esc(secondary) + '</code></td>'
            + '<td class="muted updated">' + esc(fmtDate(t.updatedAt)) + '</td>'
            + '<td class="actions"><a class="actionBtn ' + esc(proto) + '" href="' + loginUrl + '" target="_blank" rel="noopener noreferrer">' + esc(actionLabel) + '</a></td>';
          tbody.appendChild(tr);
        }
      }

      function applyFilter() {
        const query = norm(q && 'value' in q ? q.value : '');
        const filtered = !query
          ? allTenants
          : allTenants.filter((t) => norm(t.tenantId).includes(query));
        renderTenants(filtered);
        if (msg) {
          msg.innerHTML =
            filtered.length === 0
              ? '<div class="empty">No tenants match your search.</div>'
              : '';
        }
        if (wrapTbl) wrapTbl.style.display = filtered.length ? '' : 'none';
      }

      async function loadTenants() {
        msg.innerHTML = '<div class="muted">Loading...</div>';
        if (wrapTbl) wrapTbl.style.display = 'none';
        tbody.innerHTML = '';
        try {
          const res = await fetch('/admin/tenants', { credentials: 'include', headers: { 'accept': 'application/json' } });
          const text = await res.text();
          if (!res.ok) {
            msg.innerHTML = '<div class="error"><b>Error ' + res.status + '</b><div class="muted"><code>' + esc(text) + '</code></div></div>';
            return;
          }
          const data = JSON.parse(text);
          const tenants = Array.isArray(data.tenants) ? data.tenants : [];
          if (tenants.length === 0) {
            msg.innerHTML = '<div class="empty">No tenants configured.</div>';
            return;
          }
          allTenants = tenants;
          applyFilter();
        } catch (e) {
          msg.innerHTML = '<div class="error"><b>Request failed</b><div class="muted">' + esc(e && e.message ? e.message : String(e)) + '</div></div>';
        }
      }

      if (q) q.addEventListener('input', () => applyFilter());

      // Auto-load on page open
      loadTenants();
    </script>
  </body>
</html>`);
  }),
);

app.post(
  "/admin/tenants",
  asyncHandler(async (req, res) => {
    requireAdmin(req);
    const customerId = getAdminCustomerId(req) ?? "default";

    const body = AdminTenantSchema.parse(req.body);
    // Validate issuer via discovery
    await getDiscovery(body.oktaIssuer);

    const clientSecretEnc = encryptAes256Gcm(body.clientSecret, aesKey);
    const created = await prisma.tenantOidcConfig.upsert({
      where: { tenantId: body.tenantId },
      create: {
        tenantId: body.tenantId,
        customerId,
        oktaIssuer: body.oktaIssuer.replace(/\/$/, ""),
        clientId: body.clientId,
        clientSecretEnc,
        scopes: body.scopes ?? "openid profile email",
      },
      update: {
        customerId,
        oktaIssuer: body.oktaIssuer.replace(/\/$/, ""),
        clientId: body.clientId,
        clientSecretEnc,
        scopes: body.scopes ?? "openid profile email",
      },
    });

    res.json({
      tenantId: created.tenantId,
      customerId: created.customerId,
      oktaIssuer: created.oktaIssuer,
      clientId: created.clientId,
      scopes: created.scopes,
      createdAt: created.createdAt,
      updatedAt: created.updatedAt,
    });
  }),
);

// SAML removed

app.get(
  "/t/:tenantId/login",
  asyncHandler(async (req, res) => {
    const tenantId = String(req.params.tenantId);
    const tenant = await prisma.tenantOidcConfig.findUnique({ where: { tenantId } });
    if (!tenant) throw httpError(404, "Unknown tenant");

    const redirectTo = safeRelativeRedirect(
      typeof req.query.redirectTo === "string" ? req.query.redirectTo : `/t/${encodeURIComponent(tenantId)}/landing`,
    );
    const state = randomUrlSafeString(32);
    const nonce = randomUrlSafeString(24);
    const codeVerifier = randomUrlSafeString(48);
    const codeChallenge = sha256Base64Url(codeVerifier);

    await prisma.loginTransaction.create({
      data: { state, tenantId, nonce, codeVerifier, redirectTo },
    });

    const authorizeUrl = await buildAuthorizeUrl({
      issuer: tenant.oktaIssuer,
      clientId: tenant.clientId,
      redirectUri: `${env.PUBLIC_BASE_URL.replace(/\/$/, "")}/oidc/callback`,
      scope: tenant.scopes,
      state,
      nonce,
      codeChallenge,
    });

    res.redirect(authorizeUrl);
  }),
);

app.get(
  "/t/:tenantId/saml/metadata",
  asyncHandler(async (req, res) => {
    const tenantId = String(req.params.tenantId);
    const cfg = await prisma.tenantSamlConfig.findUnique({ where: { tenantId } });
    if (!cfg) throw httpError(404, "Unknown SAML tenant");
    const saml = buildSamlClient({ tenantId, idpSsoUrl: cfg.idpSsoUrl, idpCert: cfg.idpCert, idpEntityId: cfg.idpEntityId });
    const xml = saml.generateServiceProviderMetadata(null, null);
    res.type("application/xml").send(xml);
  }),
);

app.get(
  "/t/:tenantId/saml/login",
  asyncHandler(async (req, res) => {
    const tenantId = String(req.params.tenantId);
    const cfg = await prisma.tenantSamlConfig.findUnique({ where: { tenantId } });
    if (!cfg) throw httpError(404, "Unknown SAML tenant");

    const redirectTo = safeRelativeRedirect(
      typeof req.query.redirectTo === "string" ? req.query.redirectTo : `/t/${encodeURIComponent(tenantId)}/saml/landing`,
    );
    const relayState = randomUrlSafeString(32);
    await prisma.samlLoginTransaction.create({ data: { relayState, tenantId, redirectTo } });

    const saml = buildSamlClient({ tenantId, idpSsoUrl: cfg.idpSsoUrl, idpCert: cfg.idpCert, idpEntityId: cfg.idpEntityId });
    const url = await saml.getAuthorizeUrlAsync(relayState, undefined, {});
    res.redirect(url);
  }),
);

app.post(
  "/saml/acs",
  express.urlencoded({ extended: false, limit: "200kb" }),
  asyncHandler(async (req, res) => {
    const samlResponse = typeof (req.body as any)?.SAMLResponse === "string" ? (req.body as any).SAMLResponse : undefined;
    const relayState = typeof (req.body as any)?.RelayState === "string" ? (req.body as any).RelayState : undefined;
    if (!samlResponse || !relayState) throw httpError(400, "Missing SAMLResponse/RelayState");

    const txn = await prisma.samlLoginTransaction.findUnique({ where: { relayState } });
    if (!txn) throw httpError(400, "Invalid RelayState");

    const cfg = await prisma.tenantSamlConfig.findUnique({ where: { tenantId: txn.tenantId } });
    if (!cfg) throw httpError(400, "Invalid SAML tenant");

    const saml = buildSamlClient({ tenantId: cfg.tenantId, idpSsoUrl: cfg.idpSsoUrl, idpCert: cfg.idpCert, idpEntityId: cfg.idpEntityId });
    const { profile } = await saml.validatePostResponseAsync({ SAMLResponse: samlResponse });
    if (!profile) throw httpError(400, "Invalid SAML profile");
    const profileSafe = toJsonSafe(profile) as Prisma.InputJsonValue;

    const subject =
      typeof (profile as any).nameID === "string"
        ? (profile as any).nameID
        : typeof (profile as any).email === "string"
          ? (profile as any).email
          : "";
    if (!subject) throw httpError(400, "Missing subject");

    const samlResponseXml = Buffer.from(samlResponse, "base64").toString("utf8");
    const assertionXml =
      samlResponseXml.match(/<(?:\w+:)?Assertion[\s\S]*?<\/(?:\w+:)?Assertion>/)?.[0] ??
      samlResponseXml.match(/<Assertion[\s\S]*?<\/Assertion>/)?.[0] ??
      "";

    const sessionId = randomUrlSafeString(32);
    const expiresAt = new Date(Date.now() + 1000 * 60 * 60 * 8);
    const tokenSetEnc = encryptAes256Gcm(
      JSON.stringify({ protocol: "saml", samlResponseXml, assertionXml, profile: profileSafe }),
      aesKey,
    );
    await prisma.session.create({
      data: {
        id: sessionId,
        tenantId: cfg.tenantId,
        subject,
        claims: profileSafe,
        tokenSetEnc,
        expiresAt,
      },
    });

    await prisma.samlLoginTransaction.delete({ where: { relayState } }).catch(() => {});
    setSessionCookie(res, sessionId);
    res.redirect(safeRelativeRedirect(txn.redirectTo));
  }),
);

// SAML removed

app.get(
  "/oidc/callback",
  asyncHandler(async (req, res) => {
    const oauthError = typeof req.query.error === "string" ? req.query.error : undefined;
    const oauthErrorDesc = typeof req.query.error_description === "string" ? req.query.error_description : undefined;
    const code = typeof req.query.code === "string" ? req.query.code : undefined;
    const state = typeof req.query.state === "string" ? req.query.state : undefined;
    if (oauthError) {
      throw httpError(400, `OIDC error: ${oauthError}${oauthErrorDesc ? ` (${oauthErrorDesc})` : ""}`);
    }
    if (!code || !state) throw httpError(400, "Missing code/state");

    const txn = await prisma.loginTransaction.findUnique({ where: { state } });
    if (!txn) throw httpError(400, "Invalid state");

    const tenant = await prisma.tenantOidcConfig.findUnique({ where: { tenantId: txn.tenantId } });
    if (!tenant) throw httpError(400, "Invalid tenant");

    const clientSecret = decryptAes256Gcm(tenant.clientSecretEnc, aesKey);
    const redirectUri = `${env.PUBLIC_BASE_URL.replace(/\/$/, "")}/oidc/callback`;

    const tokens = await exchangeCodeForTokens({
      issuer: tenant.oktaIssuer,
      clientId: tenant.clientId,
      clientSecret,
      code,
      redirectUri,
      codeVerifier: txn.codeVerifier,
    });
    if (!tokens.id_token) throw httpError(400, "Missing id_token");

    const claims = await verifyIdToken({
      issuer: tenant.oktaIssuer,
      clientId: tenant.clientId,
      idToken: tokens.id_token,
      nonce: txn.nonce,
    });

    const subject = typeof claims.sub === "string" ? claims.sub : "";
    if (!subject) throw httpError(400, "Missing subject");

    const sessionId = randomUrlSafeString(32);
    const expiresAt = new Date(Date.now() + 1000 * 60 * 60 * 8);
    const tokenSetEnc = encryptAes256Gcm(JSON.stringify(tokens), aesKey);
    await prisma.session.create({
      data: {
        id: sessionId,
        tenantId: tenant.tenantId,
        subject,
        claims: claims as Prisma.InputJsonValue,
        tokenSetEnc,
        expiresAt,
      },
    });

    // one-time use state
    await prisma.loginTransaction.delete({ where: { state } }).catch(() => {});

    setSessionCookie(res, sessionId);
    res.redirect(safeRelativeRedirect(txn.redirectTo));
  }),
);

app.get(
  "/t/:tenantId/landing",
  asyncHandler(async (req, res) => {
    const tenantId = String(req.params.tenantId);
    const session = await requireSession(req);
    if (session.tenantId !== tenantId) {
      // This commonly happens if the user opens /landing for a different tenant while already
      // authenticated. Instead of showing a confusing 403, send them to the correct landing.
      return res.redirect(`/t/${encodeURIComponent(session.tenantId)}/landing`);
    }

    let tokenSet: any = null;
    if (session.tokenSetEnc) {
      try {
        tokenSet = JSON.parse(decryptAes256Gcm(session.tokenSetEnc, aesKey));
      } catch {
        tokenSet = null;
      }
    }
    const claims = session.claims as Record<string, unknown>;
    const sessionJwt = await createSessionJwt({
      id: session.id,
      tenantId: session.tenantId,
      subject: session.subject,
      expiresAt: session.expiresAt,
    });

    const idToken = tokenSet?.id_token ?? "";
    const accessToken = tokenSet?.access_token ?? "";

    res.type("html").send(`<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Backupta • Session tokens</title>
    <style>
      :root {
        color-scheme: light dark;
        --bg: #f8fafc;
        --panel: #ffffff;
        --text: #0f172a;
        --muted: #475569;
        --border: #e2e8f0;
        --shadow: 0 1px 2px rgba(2, 6, 23, 0.05), 0 12px 28px rgba(2, 6, 23, 0.08);
        --brand: #2563eb;
        --brand2: #0ea5e9;
        --radius: 14px;
        --decodedBoxH: 220px;
      }
      @media (prefers-color-scheme: dark) {
        :root {
          --bg: #0b1220;
          --panel: rgba(15, 23, 42, 0.6);
          --text: #e2e8f0;
          --muted: rgba(226, 232, 240, 0.72);
          --border: rgba(226, 232, 240, 0.12);
          --shadow: 0 1px 2px rgba(0,0,0,0.35), 0 14px 38px rgba(0,0,0,0.45);
        }
      }
      * { box-sizing: border-box; }
      body {
        margin: 0;
        color: var(--text);
        font-family: Inter, ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial;
      }
      .wrap { width: 100%; max-width: 1440px; margin: 22px auto; padding: 0 24px 42px; }
      .topbar {
        display: flex; align-items: center; justify-content: space-between;
        padding: 14px 16px; border: 1px solid var(--border); border-radius: var(--radius);
        background: var(--panel); box-shadow: var(--shadow);
        backdrop-filter: blur(10px);
      }
      .brand { display: flex; align-items: center; gap: 10px; min-width: 0; }
      .logoChip { display: inline-flex; align-items: center; justify-content: center; padding: 0; border-radius: 12px; }
      .brand-title { display: flex; flex-direction: column; line-height: 1.15; min-width: 0; }
      .brand-title strong { font-size: 13px; letter-spacing: 0.12em; text-transform: uppercase; }
      .brand-title span { font-size: 12px; color: var(--muted); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
      .nav { display: flex; gap: 8px; }
      .pill {
        display: inline-flex; align-items: center; gap: 8px;
        padding: 10px 12px; border-radius: 999px; border: 1px solid var(--border);
        background: rgba(127,127,127,0.08); text-decoration: none; font-weight: 650; font-size: 13px;
        color: inherit;
      }
      .pill.primary { border-color: rgba(99, 91, 255, 0.28); background: rgba(99, 91, 255, 0.12); }
      .card {
        margin-top: 16px;
        border: 1px solid var(--border); border-radius: var(--radius);
        background: var(--panel); box-shadow: var(--shadow);
        padding: 18px; backdrop-filter: blur(10px);
      }
      h1 { margin: 0 0 6px; font-size: 20px; letter-spacing: -0.02em; }
      p { margin: 0 0 14px; color: var(--muted); font-size: 14px; line-height: 1.55; }
      .grid { display: grid; grid-template-columns: 1fr; gap: 14px; }
      @media (min-width: 980px) { .grid { grid-template-columns: 1fr 1fr; } }
      .stats { display: grid; grid-template-columns: 1fr; gap: 10px; margin-top: 12px; }
      @media (min-width: 760px) { .stats { grid-template-columns: 1fr 1fr; } }
      @media (min-width: 1100px) { .stats { grid-template-columns: 1fr 1fr 1fr; } }
      .stat {
        padding: 12px 12px;
        border: 1px solid var(--border);
        border-radius: 12px;
        background: rgba(127,127,127,0.06);
        min-width: 0;
      }
      .label { color: var(--muted); font-weight: 750; font-size: 12px; text-transform: uppercase; letter-spacing: 0.08em; }
      .value { margin-top: 6px; font-weight: 700; font-size: 14px; overflow-wrap: anywhere; }
      .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 12px; font-weight: 650; }
      details { margin-top: 10px; }
      summary { cursor: pointer; color: var(--text); font-weight: 750; }
      textarea {
        width: 100%;
        min-height: 180px;
        padding: 12px;
        border-radius: 12px;
        border: 1px solid var(--border);
        background: rgba(2, 6, 23, 0.85);
        color: #e2e8f0;
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
        font-size: 13px;
        line-height: 1.45;
        resize: vertical;
        max-width: 100%;
      }
      .jwtInputArea { min-height: 110px; }
      /* Presentation-friendly: keep page height stable; scroll inside boxes */
      .tokenArea { min-height: 105px; height: 120px; overflow: auto; resize: none; }

      /* Compact summary card so the whole page fits */
      .card.compact { padding: 14px; }
      .card.compact p { margin-bottom: 10px; }
      .card.compact .stats { gap: 8px; margin-top: 10px; }
      .card.compact .stat { padding: 10px 10px; }
      .card.compact details { margin-top: 8px; }
      .row { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
      .copy {
        padding: 10px 12px;
        border-radius: 12px;
        border: 1px solid rgba(37,99,235,0.25);
        background: var(--brand);
        color: white;
        font-weight: 750;
        cursor: pointer;
        font-size: 13px;
      }
      .copy.secondary {
        background: rgba(127,127,127,0.08);
        color: var(--text);
        border: 1px solid var(--border);
        font-weight: 700;
      }
      .decoderGrid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
      @media (max-width: 920px) { .decoderGrid { grid-template-columns: 1fr; } }
      .miniDecoderGrid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-top: 10px; }
      @media (max-width: 920px) { .miniDecoderGrid { grid-template-columns: 1fr; } }
      pre {
        margin: 0;
        padding: 12px;
        border-radius: 12px;
        border: 1px solid var(--border);
        overflow: auto;
        background: rgba(2, 6, 23, 0.88);
        color: #e5e7eb;
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
        font-size: 13px;
        line-height: 1.45;
        height: var(--decodedBoxH);
        white-space: pre-wrap;
        overflow-wrap: anywhere;
        word-break: break-word;
        max-width: 100%;
      }
      .miniDecoderGrid pre { height: var(--decodedBoxH); }
      /* jwt.io-ish JSON syntax colors */
      .j-key { color: #7dd3fc; }
      .j-string { color: #a7f3d0; }
      .j-number { color: #fca5a5; }
      .j-boolean { color: #fbbf24; }
      .j-null { color: #c4b5fd; }
      .j-punct { color: rgba(229,231,235,0.75); }
      .muted { color: var(--muted); font-size: 12px; }
    </style>
    <link rel="stylesheet" href="/admin-assets/backupta-pages.css?v=2" />
  </head>
  <body>
    <div class="wrap">
      <div class="topbar">
        <div class="brand">
          <span class="logoChip">
            <img src="/admin-assets/backupta-logo-full-white.png" alt="Backupta" style="height: 18px; width: auto; display:block" />
          </span>
          <div class="brand-title">
            <strong>OIDC Broker</strong>
            <span>Session tokens</span>
          </div>
        </div>
        <div class="nav">
          <a class="pill" href="/t/${escapeHtmlAttr(tenantId)}/me">/me</a>
          <a class="pill" href="/t/${escapeHtmlAttr(tenantId)}/login">Re-login</a>
          <a class="pill primary" href="/admin/tenants">Admin</a>
        </div>
      </div>

      <div class="card compact">
        <h1>SSO session summary</h1>
        <p>
          Single sign-on is active for tenant <span class="mono">${escapeHtml(tenantId)}</span>.
          Your identity was verified by Okta, and a Backupta session was established.
        </p>

        <div class="stats">
          <div class="stat"><div class="label">User</div><div class="value">${escapeHtml(String(claims.name ?? claims.preferred_username ?? claims.email ?? ""))}</div></div>
          <div class="stat"><div class="label">Email</div><div class="value">${escapeHtml(String(claims.email ?? ""))}</div></div>
          <div class="stat"><div class="label">Okta issuer</div><div class="value mono">${escapeHtml(String(claims.iss ?? ""))}</div></div>
          <div class="stat"><div class="label">Audience (app)</div><div class="value mono">${escapeHtml(String(claims.aud ?? ""))}</div></div>
          <div class="stat"><div class="label">Authenticated at</div><div class="value">${escapeHtml(
            typeof claims.auth_time === "number" ? new Date(claims.auth_time * 1000).toISOString() : "",
          )}</div></div>
          <div class="stat"><div class="label">Session expires</div><div class="value">${escapeHtml(session.expiresAt.toISOString())}</div></div>
        </div>

        <details>
          <summary>Identity details (technical)</summary>
          <div class="stats">
            <div class="stat"><div class="label">Subject (sub)</div><div class="value mono">${escapeHtml(String(claims.sub ?? ""))}</div></div>
            <div class="stat"><div class="label">IDP</div><div class="value mono">${escapeHtml(String(claims.idp ?? ""))}</div></div>
            <div class="stat"><div class="label">Methods (amr)</div><div class="value mono">${escapeHtml(Array.isArray(claims.amr) ? claims.amr.join(", ") : String(claims.amr ?? ""))}</div></div>
          </div>
        </details>
      </div>

      <div class="grid">
        <div class="card" style="grid-column: 1 / -1">
          <div class="row" style="flex-wrap: wrap; justify-content: space-between">
            <h1 style="margin:0">JWT decoder</h1>
            <div style="display:flex; gap:8px; flex-wrap: wrap">
              <button class="copy secondary" type="button" data-load="idToken">Load ID token</button>
              <button class="copy secondary" type="button" data-load="accessToken">Load access token</button>
            </div>
          </div>
          <p class="muted">
            Paste a JWT to decode its <code>header</code> and <code>payload</code>. This is a viewer only (no signature verification).
          </p>
          <textarea id="jwtInput" class="jwtInputArea" spellcheck="false" placeholder="Paste a JWT here (three dot-separated parts)"></textarea>
          <div style="height:12px"></div>
          <div class="decoderGrid">
            <div>
              <div class="muted" style="margin:0 0 6px">Decoded header</div>
              <pre id="jwtHeader">(paste a token)</pre>
            </div>
            <div>
              <div class="muted" style="margin:0 0 6px">Decoded payload</div>
              <pre id="jwtPayload">(paste a token)</pre>
            </div>
          </div>
        </div>
        <div class="card">
          <div class="row">
            <h1 style="margin:0">ID Token</h1>
            <button class="copy" type="button" data-copy="idToken">Copy</button>
          </div>
          <p class="muted">OIDC <code>id_token</code> from Okta.</p>
          <textarea id="idToken" class="tokenArea" readonly>${escapeHtml(idToken)}</textarea>
          <div class="miniDecoderGrid">
            <div>
              <div class="muted" style="margin:0 0 6px">Decoded header</div>
              <pre id="idTokenHeader">(not a JWT)</pre>
            </div>
            <div>
              <div class="muted" style="margin:0 0 6px">Decoded payload</div>
              <pre id="idTokenPayload">(not a JWT)</pre>
            </div>
          </div>
        </div>
        <div class="card">
          <div class="row">
            <h1 style="margin:0">Access Token</h1>
            <button class="copy" type="button" data-copy="accessToken">Copy</button>
          </div>
          <p class="muted">OAuth <code>access_token</code> from Okta.</p>
          <textarea id="accessToken" class="tokenArea" readonly>${escapeHtml(accessToken)}</textarea>
          <div class="miniDecoderGrid">
            <div>
              <div class="muted" style="margin:0 0 6px">Decoded header</div>
              <pre id="accessTokenHeader">(not a JWT)</pre>
            </div>
            <div>
              <div class="muted" style="margin:0 0 6px">Decoded payload</div>
              <pre id="accessTokenPayload">(not a JWT)</pre>
            </div>
          </div>
        </div>
      </div>
    </div>

    <script>
      function copyFrom(id) {
        const el = document.getElementById(id);
        el.focus();
        el.select();
        document.execCommand('copy');
      }
      document.querySelectorAll('[data-copy]').forEach((btn) => {
        btn.addEventListener('click', () => {
          copyFrom(btn.getAttribute('data-copy'));
        });
      });

      function b64urlToUtf8(input) {
        const s = String(input || '').replace(/-/g, '+').replace(/_/g, '/');
        const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4));
        const bin = atob(s + pad);
        const bytes = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
        return new TextDecoder().decode(bytes);
      }

      function tryParseJson(s) {
        try { return JSON.parse(s); } catch { return null; }
      }

      function escHtml(s) {
        return String(s)
          .replaceAll('&', '&amp;')
          .replaceAll('<', '&lt;')
          .replaceAll('>', '&gt;')
          .replaceAll('"', '&quot;')
          .replaceAll("'", '&#39;');
      }

      function highlightJson(jsonText) {
        // Basic json syntax highlighting for display only.
        // Input must be a JSON string (not an object).
        const s = escHtml(String(jsonText));
        return s
          // keys: "foo":
          .replace(/(&quot;.*?&quot;)(\\s*):/g, '<span class="j-key">$1</span><span class="j-punct">$2</span>:')
          // strings: "bar"
          .replace(/:(\\s*)(&quot;.*?&quot;)/g, ':$1<span class="j-string">$2</span>')
          // numbers
          .replace(/:(\\s*)(-?\\d+(?:\\.\\d+)?(?:[eE][+-]?\\d+)?)/g, ':$1<span class="j-number">$2</span>')
          // booleans
          .replace(/:(\\s*)(true|false)\\b/g, ':$1<span class="j-boolean">$2</span>')
          // null
          .replace(/:(\\s*)null\\b/g, ':$1<span class="j-null">null</span>');
      }

      function renderJsonInto(el, obj) {
        if (!el) return;
        const txt = JSON.stringify(obj, null, 2);
        el.innerHTML = highlightJson(txt);
      }

      function fmtEpochSeconds(v) {
        if (typeof v !== 'number') return null;
        try { return new Date(v * 1000).toISOString(); } catch { return null; }
      }

      function decodeJwt(token) {
        const t = String(token || '').trim();
        if (!t) return { ok: false, error: '(paste a token)' };
        const parts = t.split('.');
        if (parts.length !== 3) return { ok: false, error: 'Not a JWT: expected 3 dot-separated parts.' };
        const [h, p] = parts;
        const headerStr = b64urlToUtf8(h);
        const payloadStr = b64urlToUtf8(p);
        const header = tryParseJson(headerStr);
        const payload = tryParseJson(payloadStr);
        if (!header || !payload) return { ok: false, error: 'Could not parse header/payload JSON.' };

        // Friendly derived fields for exec/demo audiences
        if (typeof payload.iat === 'number') payload.iat_iso = fmtEpochSeconds(payload.iat);
        if (typeof payload.exp === 'number') payload.exp_iso = fmtEpochSeconds(payload.exp);
        if (typeof payload.nbf === 'number') payload.nbf_iso = fmtEpochSeconds(payload.nbf);
        if (typeof payload.exp === 'number') payload.expires_in_seconds = Math.max(0, payload.exp - Math.floor(Date.now() / 1000));

        return { ok: true, header, payload };
      }

      const jwtInput = document.getElementById('jwtInput');
      const jwtHeader = document.getElementById('jwtHeader');
      const jwtPayload = document.getElementById('jwtPayload');

      function renderJwt() {
        if (!jwtInput || !jwtHeader || !jwtPayload) return;
        const r = decodeJwt(jwtInput.value);
        if (!r.ok) {
          jwtHeader.textContent = r.error;
          jwtPayload.textContent = r.error;
          return;
        }
        renderJsonInto(jwtHeader, r.header);
        renderJsonInto(jwtPayload, r.payload);
      }

      function renderDecodedInto(tokenElId, headerElId, payloadElId) {
        const tokenEl = document.getElementById(tokenElId);
        const headerEl = document.getElementById(headerElId);
        const payloadEl = document.getElementById(payloadElId);
        if (!tokenEl || !headerEl || !payloadEl) return;
        const token = ('value' in tokenEl) ? String(tokenEl.value || '') : '';
        const r = decodeJwt(token);
        if (!r.ok) {
          headerEl.textContent = r.error;
          payloadEl.textContent = r.error;
          return;
        }
        renderJsonInto(headerEl, r.header);
        renderJsonInto(payloadEl, r.payload);
      }

      if (jwtInput) {
        jwtInput.addEventListener('input', () => renderJwt());
      }
      document.querySelectorAll('[data-load]').forEach((btn) => {
        btn.addEventListener('click', () => {
          const srcId = btn.getAttribute('data-load');
          const src = srcId ? document.getElementById(srcId) : null;
          if (jwtInput && src && 'value' in src) {
            jwtInput.value = String(src.value || '');
            renderJwt();
            jwtInput.scrollIntoView({ block: 'center', behavior: 'smooth' });
            jwtInput.focus();
          }
        });
      });

      // Initialize with ID token to make the demo instant.
      try {
        const idEl = document.getElementById('idToken');
        if (jwtInput && idEl && 'value' in idEl) {
          jwtInput.value = String(idEl.value || '');
          renderJwt();
        }
      } catch (e) {}

      // Also decode the built-in ID/access tokens automatically.
      try {
        renderDecodedInto('idToken', 'idTokenHeader', 'idTokenPayload');
        renderDecodedInto('accessToken', 'accessTokenHeader', 'accessTokenPayload');
      } catch (e2) {}
    </script>
  </body>
</html>`);
  }),
);

app.get(
  "/t/:tenantId/saml/landing",
  asyncHandler(async (req, res) => {
    // Restored SAML landing page
    const tenantId = String(req.params.tenantId);
    const session = await requireSession(req);
    if (session.tenantId !== tenantId) {
      return res.redirect(`/t/${encodeURIComponent(session.tenantId)}/saml/landing`);
    }

    let saml: any = null;
    if (session.tokenSetEnc) {
      try {
        saml = JSON.parse(decryptAes256Gcm(String(session.tokenSetEnc), aesKey));
      } catch {
        saml = null;
      }
    }
    const profile = (saml && saml.protocol === "saml" ? saml.profile : null) ?? (session.claims as any);
    const assertionXml = saml && saml.protocol === "saml" ? String(saml.assertionXml ?? "") : "";
    const samlResponseXml = saml && saml.protocol === "saml" ? String(saml.samlResponseXml ?? "") : "";
    const attrsRaw = assertionXml ? extractSamlAttributesSimple(assertionXml) : {};
    const attrs = Object.keys(attrsRaw).length ? attrsRaw : attrsFromSamlProfile(profile);

    const nameId = typeof profile?.nameID === "string" ? profile.nameID : "";

    // Okta AttributeStatements are the source of truth for user profile fields.
    const firstName = pickAttr(attrs, [
      "firstName",
      "givenName",
      "FirstName",
      "urn:oid:2.5.4.42", // givenName
    ]);
    const lastName = pickAttr(attrs, [
      "lastName",
      "sn",
      "LastName",
      "urn:oid:2.5.4.4", // sn
    ]);
    const attrDisplayName = pickAttr(attrs, [
      "displayName",
      "DisplayName",
      "cn",
      "urn:oid:2.16.840.1.113730.3.1.241", // displayName
    ]);
    let attrEmail = pickAttr(attrs, [
      "email",
      "Email",
      "mail",
      "upn",
      "user.email",
      "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
      "urn:oid:0.9.2342.19200300.100.1.3", // mail
    ]);
    if (!attrEmail) attrEmail = guessEmailFromAttrs(attrs);

    const displayName =
      attrDisplayName ||
      [firstName, lastName].filter(Boolean).join(" ").trim() ||
      (typeof profile?.displayName === "string" ? profile.displayName : "") ||
      (typeof profile?.cn === "string" ? profile.cn : "") ||
      nameId;

    const email =
      attrEmail ||
      (typeof profile?.email === "string" ? profile.email : "") ||
      (typeof profile?.mail === "string" ? profile.mail : "") ||
      (typeof profile?.["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"] === "string"
        ? profile["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"]
        : "");

    const issuer = typeof profile?.issuer === "string" ? profile.issuer : "";
    const sessionIndex = typeof profile?.sessionIndex === "string" ? profile.sessionIndex : "";

    res.type("html").send(`<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Backupta • SAML assertion</title>
    <style>
      :root {
        color-scheme: light dark;
        --bg: #f8fafc;
        --panel: #ffffff;
        --text: #0f172a;
        --muted: #475569;
        --border: #e2e8f0;
        --shadow: 0 1px 2px rgba(2, 6, 23, 0.05), 0 12px 28px rgba(2, 6, 23, 0.08);
        --brand: #2563eb;
        --brand2: #0ea5e9;
        --radius: 14px;
        --decodedBoxH: 160px;
      }
      @media (prefers-color-scheme: dark) {
        :root {
          --bg: #0b1220;
          --panel: rgba(15, 23, 42, 0.6);
          --text: #e2e8f0;
          --muted: rgba(226, 232, 240, 0.72);
          --border: rgba(226, 232, 240, 0.12);
          --shadow: 0 1px 2px rgba(0,0,0,0.35), 0 14px 38px rgba(0,0,0,0.45);
        }
      }
      * { box-sizing: border-box; }
      body {
        margin: 0;
        color: var(--text);
        font-family: Inter, ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial;
        overflow-x: hidden;
      }
      .wrap { width: 100%; max-width: 1440px; margin: 22px auto; padding: 0 24px 42px; }
      .topbar {
        display: flex; align-items: center; justify-content: space-between;
        padding: 14px 16px; border: 1px solid var(--border); border-radius: var(--radius);
        background: var(--panel); box-shadow: var(--shadow);
        backdrop-filter: blur(10px);
      }
      .brand { display: flex; align-items: center; gap: 10px; min-width: 0; }
      .logoChip { display: inline-flex; align-items: center; justify-content: center; padding: 0; border-radius: 12px; }
      .brand-title { display: flex; flex-direction: column; line-height: 1.15; min-width: 0; }
      .brand-title strong { font-size: 13px; letter-spacing: 0.12em; text-transform: uppercase; }
      .brand-title span { font-size: 12px; color: var(--muted); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
      .nav { display: flex; gap: 8px; }
      .pill {
        display: inline-flex; align-items: center; gap: 8px;
        padding: 10px 12px; border-radius: 999px; border: 1px solid var(--border);
        background: rgba(127,127,127,0.08); text-decoration: none; font-weight: 650; font-size: 13px;
        color: inherit;
      }
      .pill.primary { border-color: rgba(99, 91, 255, 0.28); background: rgba(99, 91, 255, 0.12); }
      .card {
        margin-top: 16px;
        border: 1px solid var(--border); border-radius: var(--radius);
        background: var(--panel); box-shadow: var(--shadow);
        padding: 14px; backdrop-filter: blur(10px);
      }
      h1 { margin: 0 0 6px; font-size: 20px; letter-spacing: -0.02em; }
      p { margin: 0 0 10px; color: var(--muted); font-size: 14px; line-height: 1.55; }
      .grid { display: grid; grid-template-columns: 1fr; gap: 14px; }
      @media (min-width: 980px) { .grid { grid-template-columns: 1fr 1fr; } }
      .stats { display: grid; grid-template-columns: 1fr; gap: 8px; margin-top: 10px; }
      @media (min-width: 760px) { .stats { grid-template-columns: 1fr 1fr; } }
      @media (min-width: 1100px) { .stats { grid-template-columns: 1fr 1fr 1fr; } }
      .stat { padding: 10px 10px; border: 1px solid var(--border); border-radius: 12px; background: rgba(127,127,127,0.06); min-width: 0; }
      .label { color: var(--muted); font-weight: 750; font-size: 12px; text-transform: uppercase; letter-spacing: 0.08em; }
      .value { margin-top: 6px; font-weight: 700; font-size: 14px; overflow-wrap: anywhere; }
      .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 12px; font-weight: 650; }
      textarea {
        width: 100%;
        padding: 12px;
        border-radius: 12px;
        border: 1px solid var(--border);
        background: rgba(2, 6, 23, 0.85);
        color: #e2e8f0;
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
        font-size: 13px;
        line-height: 1.45;
        max-width: 100%;
        overflow: auto;
        resize: none;
      }
      .xmlArea { height: 160px; }
      pre {
        margin: 0;
        padding: 12px;
        border-radius: 12px;
        border: 1px solid var(--border);
        overflow: auto;
        background: rgba(2, 6, 23, 0.88);
        color: #e5e7eb;
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
        font-size: 13px;
        line-height: 1.45;
        height: var(--decodedBoxH);
        white-space: pre-wrap;
        overflow-wrap: anywhere;
        word-break: break-word;
        max-width: 100%;
      }
      .decoderGrid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
      @media (max-width: 920px) { .decoderGrid { grid-template-columns: 1fr; } }
      .j-key { color: #7dd3fc; }
      .j-string { color: #a7f3d0; }
      .j-number { color: #fca5a5; }
      .j-boolean { color: #fbbf24; }
      .j-null { color: #c4b5fd; }
      .j-punct { color: rgba(229,231,235,0.75); }
      /* samltool-ish XML syntax colors */
      .x-tag { color: #7dd3fc; }
      .x-name { color: #e5e7eb; }
      .x-attr { color: #fbbf24; }
      .x-val { color: #a7f3d0; }
      .x-punct { color: rgba(229,231,235,0.75); }
      .muted { color: var(--muted); font-size: 12px; }
      .row { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
      .copy {
        padding: 10px 12px;
        border-radius: 12px;
        border: 1px solid rgba(37,99,235,0.25);
        background: var(--brand);
        color: white;
        font-weight: 750;
        cursor: pointer;
        font-size: 13px;
      }
      .copy.secondary {
        background: rgba(127,127,127,0.08);
        color: var(--text);
        border: 1px solid var(--border);
        font-weight: 700;
      }
    </style>
    <link rel="stylesheet" href="/admin-assets/backupta-pages.css?v=2" />
  </head>
  <body>
    <div class="wrap">
      <div class="topbar">
        <div class="brand">
          <span class="logoChip">
            <img src="/admin-assets/backupta-logo-full-white.png" alt="Backupta" style="height: 18px; width: auto; display:block" />
          </span>
          <div class="brand-title">
            <strong>OIDC Broker</strong>
            <span>SAML assertion</span>
          </div>
        </div>
        <div class="nav">
          <a class="pill" href="/t/${escapeHtmlAttr(tenantId)}/saml/login">Re-login</a>
          <a class="pill primary" href="/admin/tenants">Admin</a>
        </div>
      </div>

      <div class="card">
        <h1>SSO session summary</h1>
        <p>Single sign-on is active for tenant <span class="mono">${escapeHtml(tenantId)}</span> via SAML. Your identity was verified by your IdP.</p>
        <div class="stats">
          <div class="stat"><div class="label">User</div><div class="value">${escapeHtml(displayName || "(unknown)")}</div></div>
          <div class="stat"><div class="label">NameID</div><div class="value mono">${escapeHtml(nameId)}</div></div>
          <div class="stat"><div class="label">Email</div><div class="value">${escapeHtml(email || "(not provided)")}</div></div>
          <div class="stat"><div class="label">Session expires</div><div class="value">${escapeHtml(session.expiresAt.toISOString())}</div></div>
          <div class="stat"><div class="label">Issuer</div><div class="value mono">${escapeHtml(issuer)}</div></div>
          <div class="stat"><div class="label">SessionIndex</div><div class="value mono">${escapeHtml(sessionIndex)}</div></div>
        </div>
      </div>

      <div class="grid">
        ${
          assertionXml || samlResponseXml
            ? `<div class="card" style="grid-column: 1 / -1">
          <div class="row" style="flex-wrap: wrap; justify-content: space-between">
            <h1 style="margin:0">SAML decoded</h1>
            <div style="display:flex; gap:8px; flex-wrap: wrap">
              ${assertionXml ? `<button class="copy secondary" type="button" data-load="assertion">Assertion</button>` : ``}
              ${samlResponseXml ? `<button class="copy secondary" type="button" data-load="response">Full response</button>` : ``}
            </div>
          </div>
          <p class="muted">Decoded view: pretty-printed XML.</p>
          <div class="muted" id="docHint" style="margin-top: -4px"></div>
          <div style="height:12px"></div>
          <div>
            <div class="muted" style="margin:0 0 6px">Pretty XML</div>
            <pre id="xmlPretty">(loading...)</pre>
          </div>
        </div>`
            : `<div class="card" style="grid-column: 1 / -1"><h1 style="margin:0">Assertion</h1><p class="muted">No SAML XML was captured for this session.</p></div>`
        }
      </div>
    </div>

    <script>
      function escHtml(s) {
        return String(s)
          .replaceAll('&', '&amp;')
          .replaceAll('<', '&lt;')
          .replaceAll('>', '&gt;')
          .replaceAll('"', '&quot;')
          .replaceAll("'", '&#39;');
      }

      function highlightJson(jsonText) {
        const s = escHtml(String(jsonText));
        return s
          .replace(/(&quot;.*?&quot;)(\\s*):/g, '<span class="j-key">$1</span><span class="j-punct">$2</span>:')
          .replace(/:(\\s*)(&quot;.*?&quot;)/g, ':$1<span class="j-string">$2</span>')
          .replace(/:(\\s*)(-?\\d+(?:\\.\\d+)?(?:[eE][+-]?\\d+)?)/g, ':$1<span class="j-number">$2</span>')
          .replace(/:(\\s*)(true|false)\\b/g, ':$1<span class="j-boolean">$2</span>')
          .replace(/:(\\s*)null\\b/g, ':$1<span class="j-null">null</span>');
      }

      function highlightXml(xmlText) {
        // XML syntax highlighting for display only.
        // Work on HTML-escaped text to avoid injection.
        let s = escHtml(String(xmlText));
        // Highlight tag open/close + names
        s = s.replace(/(&lt;\\/?)([A-Za-z_][A-Za-z0-9_.:-]*)([^&]*?)(\\/?&gt;)/g, function (_, p1, name, attrs, p4) {
          // attrs still escaped; highlight attributes inside
          let a = String(attrs || '');
          // attribute="value"
          a = a.replace(/\\s+([A-Za-z_][A-Za-z0-9_.:-]*)(=)(&quot;[^&]*?&quot;)/g,
            ' <span class="x-attr">$1</span><span class="x-punct">$2</span><span class="x-val">$3</span>');
          return '<span class="x-punct">' + p1 + '</span><span class="x-tag">' + name + '</span>' + a + '<span class="x-punct">' + p4 + '</span>';
        });
        return s;
      }

      function renderJsonInto(el, obj) {
        if (!el) return;
        const txt = JSON.stringify(obj, null, 2);
        el.innerHTML = highlightJson(txt);
      }

      function prettyXml(xml) {
        const s = String(xml || '').trim();
        if (!s) return '';
        // Lightweight pretty-printer (good enough for demos).
        const withNewlines = s.replace(/></g, '>\\n<');
        const lines = withNewlines.split('\\n');
        let indent = 0;
        const out = [];
        for (const line of lines) {
          const l = line.trim();
          if (l.match(/^<\\//)) indent = Math.max(0, indent - 1);
          out.push('  '.repeat(indent) + l);
          if (l.match(/^<[^!?/][^>]*[^/]>$/)) indent += 1;
        }
        return out.join('\\n');
      }

      function extractAttrsFromXml(xml) {
        const s = String(xml || '');
        const attrs = {};
        try {
          const doc = new DOMParser().parseFromString(s, 'text/xml');
          const all = doc.getElementsByTagName('*');
          for (let i = 0; i < all.length; i++) {
            const el = all[i];
            if (!el || el.localName !== 'Attribute') continue;
            const name = el.getAttribute('Name') || el.getAttribute('name') || '';
            if (!name) continue;
            const values = [];
            const kids = el.getElementsByTagName('*');
            for (let j = 0; j < kids.length; j++) {
              const kv = kids[j];
              if (kv && kv.localName === 'AttributeValue') {
                const txt = (kv.textContent || '').trim();
                if (txt) values.push(txt);
              }
            }
            (attrs)[name] = values.length <= 1 ? (values[0] ?? '') : values;
          }
          if (Object.keys(attrs).length) return attrs;
        } catch (e) {}

        // Fallback regex (namespace-tolerant)
        const attrRe = /<(?:\\w+:)?Attribute\\b[^>]*\\bName="([^"]+)"[^>]*>([\\s\\S]*?)<\\/(?:\\w+:)?Attribute>/g;
        let m;
        while ((m = attrRe.exec(s))) {
          const name = m[1];
          const inner = m[2] || '';
          const values = [];
          const valRe = /<(?:\\w+:)?AttributeValue\\b[^>]*>([\\s\\S]*?)<\\/(?:\\w+:)?AttributeValue>/g;
          let v;
          while ((v = valRe.exec(inner))) {
            values.push(v[1].replace(/<[^>]+>/g, '').trim());
          }
          (attrs)[name] = values.length <= 1 ? (values[0] ?? '') : values;
        }
        return attrs;
      }

      const xmlPretty = document.getElementById('xmlPretty');
      // Extracted attributes panel removed (XML-only view)
      const docHint = document.getElementById('docHint');

      const ASSERTION_XML = ${JSON.stringify(assertionXml)};
      const RESPONSE_XML = ${JSON.stringify(samlResponseXml)};
      let current = ASSERTION_XML && ASSERTION_XML.trim() ? 'assertion' : (RESPONSE_XML && RESPONSE_XML.trim() ? 'response' : '');

      function renderDecoded(which) {
        if (!xmlPretty) return;
        const xml = which === 'response' ? RESPONSE_XML : ASSERTION_XML;
        if (docHint) docHint.textContent = which === 'response' ? 'Showing: full SAML Response' : 'Showing: Assertion';
        if (!String(xml || '').trim()) {
          xmlPretty.textContent = '(no XML available)';
          return;
        }
        const pretty = prettyXml(xml);
        xmlPretty.innerHTML = highlightXml(pretty);
      }

      document.querySelectorAll('[data-load]').forEach((btn) => {
        btn.addEventListener('click', () => {
          const src = btn.getAttribute('data-load');
          current = (src === 'response') ? 'response' : 'assertion';
          renderDecoded(current);
        });
      });

      renderDecoded(current || 'assertion');
    </script>
  </body>
</html>`);
  }),
);

app.get(
  "/t/:tenantId/me",
  asyncHandler(async (req, res) => {
    const tenantId = String(req.params.tenantId);
    const session = await requireSession(req);
    if (session.tenantId !== tenantId) {
      res.status(403).json({
        error: "Wrong tenant",
        sessionTenantId: session.tenantId,
        requestedTenantId: tenantId,
        hint: "Start login again at /t/<tenantId>/login to switch tenants.",
      });
      return;
    }
    const claims = session.claims as Record<string, unknown>;
    res.json({
      tenantId,
      sub: claims.sub,
      email: claims.email,
      name: claims.name,
      preferred_username: claims.preferred_username,
      claims,
    });
  }),
);

app.post(
  "/t/:tenantId/logout",
  asyncHandler(async (req, res) => {
    const tenantId = String(req.params.tenantId);
    const session = await requireSession(req).catch(() => null);
    if (session && session.tenantId === tenantId) {
      await prisma.session.delete({ where: { id: session.id } }).catch(() => {});
    }
    clearSessionCookie(res);

    const tenant = await prisma.tenantOidcConfig.findUnique({ where: { tenantId } });
    if (tenant) {
      const discovery = await getDiscovery(tenant.oktaIssuer).catch(() => null);
      if (discovery?.end_session_endpoint) {
        return res.json({ ok: true, endSessionEndpoint: discovery.end_session_endpoint });
      }
    }
    res.json({ ok: true });
  }),
);

// Root URL (e.g. opening the Fly app hostname in a browser)
app.get("/", (_req, res) => {
  res.redirect(302, "/admin/login");
});

// Basic healthcheck
app.get("/healthz", (_req, res) => res.json({ ok: true }));

// Cleanup old transactions/sessions periodically (best-effort)
setInterval(async () => {
  const cutoff = new Date(Date.now() - 1000 * 60 * 15);
  await prisma.loginTransaction.deleteMany({ where: { createdAt: { lt: cutoff } } }).catch(() => {});
  await prisma.session.deleteMany({ where: { expiresAt: { lt: new Date() } } }).catch(() => {});
}, 60_000).unref();

// Error handler (no secret leakage)
app.use((err: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  const status = typeof err === "object" && err && "status" in err ? Number((err as any).status) : 500;
  const code = Number.isFinite(status) ? status : 500;
  // Zod validation errors should be 400, not 500.
  if (err instanceof z.ZodError) {
    const accept = String(_req.header("accept") ?? "");
    const payload = { error: err.issues };
    if (accept.includes("text/html")) {
      res.status(400).type("html").send(`<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Backupta • Error</title>
    <link rel="stylesheet" href="/admin-assets/backupta-pages.css?v=2" />
  </head>
  <body style="font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial; padding: 24px">
    <h1 style="margin:0 0 8px">Invalid request</h1>
    <pre style="white-space:pre-wrap; overflow-wrap:anywhere; background:#0b1220; color:#e2e8f0; padding:12px; border-radius:12px">${escapeHtml(
      JSON.stringify(payload, null, 2),
    )}</pre>
  </body>
</html>`);
      return;
    }
    res.status(400).json(payload);
    return;
  }

  const message = err instanceof Error ? err.message : "Internal error";
  const accept = String(_req.header("accept") ?? "");
  if (accept.includes("text/html")) {
    res
      .status(code)
      .type("html")
      .send(`<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Backupta • Error</title>
    <style>
      :root { color-scheme: light dark; --bg:#f8fafc; --panel:#ffffff; --text:#0f172a; --muted:#475569; --border:#e2e8f0; --shadow:0 1px 2px rgba(2,6,23,0.05),0 12px 28px rgba(2,6,23,0.08); --brand:#2563eb; --radius:14px; }
      @media (prefers-color-scheme: dark){ :root{ --bg:#0b1220; --panel:rgba(15,23,42,0.6); --text:#e2e8f0; --muted:rgba(226,232,240,0.72); --border:rgba(226,232,240,0.12); --shadow:0 1px 2px rgba(0,0,0,0.35),0 14px 38px rgba(0,0,0,0.45);} }
      *{box-sizing:border-box} body{margin:0;color:var(--text);font-family:Inter,ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial;}
      .wrap{width:100%;max-width:900px;margin:28px auto;padding:0 24px 42px;}
      .card{margin-top:16px;border:1px solid var(--border);border-radius:var(--radius);background:var(--panel);box-shadow:var(--shadow);padding:18px;backdrop-filter:blur(10px);}
      h1{margin:0 0 6px;font-size:20px;letter-spacing:-0.02em}
      p{margin:0 0 14px;color:var(--muted);font-size:14px;line-height:1.55}
      .pill{display:inline-flex;align-items:center;gap:8px;padding:10px 12px;border-radius:999px;border:1px solid var(--border);background:rgba(127,127,127,0.08);text-decoration:none;font-weight:650;font-size:13px;color:inherit}
      .pill.primary{border-color:rgba(37,99,235,0.25);background:rgba(37,99,235,0.06)}
      code{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;font-size:12px}
      pre{margin:0;padding:12px;border-radius:12px;border:1px solid var(--border);overflow:auto;background:rgba(127,127,127,0.06)}
    </style>
    <link rel="stylesheet" href="/admin-assets/backupta-pages.css?v=2" />
  </head>
  <body>
    <div class="wrap">
      <div class="card">
        <h1>Request failed</h1>
        <p>Status: <code>${escapeHtml(String(code))}</code></p>
        <pre>${escapeHtml(String(message))}</pre>
        <div style="height:12px"></div>
        <a class="pill primary" href="/admin/tenants">Go to Admin</a>
        <a class="pill" href="/">Home</a>
      </div>
    </div>
  </body>
</html>`);
    return;
  }
  res.status(code).json({ error: message });
});

// On Vercel the app runs as a serverless function (see api/index.ts), so we
// must NOT bind a port. Locally / on a container host we start a normal server.
if (!process.env.VERCEL) {
  app.listen(env.PORT, "0.0.0.0", () => {
    // eslint-disable-next-line no-console
    console.log(`oidc-broker listening on ${env.PUBLIC_BASE_URL}`);
  });
}

export default app;

