import { createRemoteJWKSet, jwtVerify, type JWTPayload } from "jose";

export type Auth0AdminConfig = {
  issuer: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  /** If set, only these emails (lowercase) may obtain an admin session. */
  allowedEmails?: string[];
  /** Namespaced JWT claim used as broker workspace / customerId (falls back to "default"). */
  workspaceClaim?: string;
};

export function auth0IssuerFromDomain(domain: string): string {
  const host = String(domain ?? "")
    .trim()
    .replace(/^https?:\/\//i, "")
    .replace(/\/+$/, "");
  if (!host) throw new Error("AUTH0_DOMAIN is empty");
  return `https://${host}/`;
}

export function buildAuth0AuthorizeUrl(cfg: Auth0AdminConfig, state: string, nonce: string): string {
  const u = new URL("authorize", cfg.issuer);
  u.searchParams.set("response_type", "code");
  u.searchParams.set("client_id", cfg.clientId);
  u.searchParams.set("redirect_uri", cfg.redirectUri);
  u.searchParams.set("scope", "openid profile email");
  u.searchParams.set("state", state);
  u.searchParams.set("nonce", nonce);
  return u.toString();
}

export async function exchangeAuth0Code(cfg: Auth0AdminConfig, code: string): Promise<{ id_token: string }> {
  const tokenUrl = new URL("oauth/token", cfg.issuer);
  const res = await fetch(tokenUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      grant_type: "authorization_code",
      client_id: cfg.clientId,
      client_secret: cfg.clientSecret,
      code,
      redirect_uri: cfg.redirectUri,
    }),
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`Auth0 token exchange failed (${res.status}): ${text.slice(0, 500)}`);
  let json: { id_token?: string };
  try {
    json = JSON.parse(text) as { id_token?: string };
  } catch {
    throw new Error("Auth0 token response was not JSON");
  }
  if (!json.id_token) throw new Error("Auth0 token response missing id_token");
  return { id_token: json.id_token };
}

export async function verifyAuth0IdToken(cfg: Auth0AdminConfig, id_token: string, expectedNonce: string): Promise<JWTPayload> {
  const jwksUrl = new URL(".well-known/jwks.json", cfg.issuer);
  const JWKS = createRemoteJWKSet(jwksUrl);
  const { payload } = await jwtVerify(id_token, JWKS, {
    issuer: cfg.issuer,
    audience: cfg.clientId,
    maxTokenAge: "2h",
  });
  const n = typeof payload.nonce === "string" ? payload.nonce : "";
  if (!n || n !== expectedNonce) throw new Error("Invalid or missing id_token nonce");
  return payload;
}

function claimFromPayload(payload: JWTPayload, claimName: string): unknown {
  if (!claimName) return undefined;
  const direct = (payload as Record<string, unknown>)[claimName];
  if (direct !== undefined && direct !== null) return direct;
  // Optional dotted path for nested custom claims (rare)
  const parts = claimName.split(".");
  let cur: unknown = payload;
  for (const p of parts) {
    if (cur == null || typeof cur !== "object") return undefined;
    cur = (cur as Record<string, unknown>)[p];
  }
  return cur;
}

export function workspaceFromAuth0Payload(payload: JWTPayload, workspaceClaim?: string): string {
  const raw = workspaceClaim ? claimFromPayload(payload, workspaceClaim) : undefined;
  const s = raw == null ? "" : String(raw).trim();
  if (!s) return "default";
  if (!/^[a-zA-Z0-9_.-]+$/.test(s)) return "default";
  return s;
}

export function parseAllowedEmailsCsv(csv: string | undefined): string[] | undefined {
  if (!csv?.trim()) return undefined;
  const list = csv
    .split(",")
    .map((e) => e.trim().toLowerCase())
    .filter(Boolean);
  return list.length ? list : undefined;
}
