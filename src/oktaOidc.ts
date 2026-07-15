import { createRemoteJWKSet, jwtVerify } from "jose";
import { getDiscovery } from "./oidcCache.js";

export type TokenSet = {
  id_token: string;
  access_token?: string;
  refresh_token?: string;
  token_type?: string;
  expires_in?: number;
  scope?: string;
};

function formUrlEncoded(data: Record<string, string>): string {
  return new URLSearchParams(data).toString();
}

async function postForm(url: string, body: Record<string, string>, headers?: Record<string, string>) {
  const res = await fetch(url, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      accept: "application/json",
      ...headers,
    },
    body: formUrlEncoded(body),
  });
  const json = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(`Token exchange failed (${res.status})`);
  }
  return json as TokenSet;
}

export async function buildAuthorizeUrl(opts: {
  issuer: string;
  clientId: string;
  redirectUri: string;
  scope: string;
  state: string;
  nonce: string;
  codeChallenge: string;
}): Promise<string> {
  const discovery = await getDiscovery(opts.issuer);
  const url = new URL(discovery.authorization_endpoint);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", opts.clientId);
  url.searchParams.set("redirect_uri", opts.redirectUri);
  url.searchParams.set("scope", opts.scope);
  url.searchParams.set("state", opts.state);
  url.searchParams.set("nonce", opts.nonce);
  url.searchParams.set("code_challenge", opts.codeChallenge);
  url.searchParams.set("code_challenge_method", "S256");
  return url.toString();
}

export async function exchangeCodeForTokens(opts: {
  issuer: string;
  clientId: string;
  clientSecret: string;
  code: string;
  redirectUri: string;
  codeVerifier: string;
}): Promise<TokenSet> {
  const discovery = await getDiscovery(opts.issuer);
  return await postForm(
    discovery.token_endpoint,
    {
      grant_type: "authorization_code",
      code: opts.code,
      redirect_uri: opts.redirectUri,
      code_verifier: opts.codeVerifier,
    },
    {
      authorization: `Basic ${Buffer.from(`${opts.clientId}:${opts.clientSecret}`).toString("base64")}`,
    },
  );
}

export async function verifyIdToken(opts: {
  issuer: string;
  clientId: string;
  idToken: string;
  nonce: string;
}): Promise<Record<string, unknown>> {
  const discovery = await getDiscovery(opts.issuer);
  const jwks = createRemoteJWKSet(new URL(discovery.jwks_uri));
  const { payload } = await jwtVerify(opts.idToken, jwks, {
    issuer: discovery.issuer,
    audience: opts.clientId,
  });
  if (payload.nonce !== opts.nonce) throw new Error("Invalid nonce");
  return payload as Record<string, unknown>;
}

