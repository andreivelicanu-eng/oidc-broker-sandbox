type CacheEntry<T> = {
  value: T;
  expiresAtMs: number;
};

export class TtlCache<K, V> {
  private map = new Map<K, CacheEntry<V>>();
  constructor(private ttlMs: number) {}

  get(key: K): V | undefined {
    const entry = this.map.get(key);
    if (!entry) return undefined;
    if (Date.now() > entry.expiresAtMs) {
      this.map.delete(key);
      return undefined;
    }
    return entry.value;
  }

  set(key: K, value: V, ttlMsOverride?: number) {
    const ttl = ttlMsOverride ?? this.ttlMs;
    this.map.set(key, { value, expiresAtMs: Date.now() + ttl });
  }

  delete(key: K) {
    this.map.delete(key);
  }
}

export type OidcDiscovery = {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
  end_session_endpoint?: string;
};

async function fetchJson(url: string): Promise<unknown> {
  const res = await fetch(url, { headers: { accept: "application/json" } });
  if (!res.ok) throw new Error(`Failed to fetch ${url}: ${res.status}`);
  return await res.json();
}

export const discoveryCache = new TtlCache<string, OidcDiscovery>(60 * 60 * 1000);

export async function getDiscovery(issuer: string): Promise<OidcDiscovery> {
  const cached = discoveryCache.get(issuer);
  if (cached) return cached;
  const url = `${issuer.replace(/\/$/, "")}/.well-known/openid-configuration`;
  const data = await fetchJson(url);
  if (typeof data !== "object" || data === null) throw new Error("Invalid discovery document");
  const obj = data as Record<string, unknown>;
  const discovery: OidcDiscovery = {
    issuer: String(obj.issuer ?? ""),
    authorization_endpoint: String(obj.authorization_endpoint ?? ""),
    token_endpoint: String(obj.token_endpoint ?? ""),
    jwks_uri: String(obj.jwks_uri ?? ""),
    end_session_endpoint: obj.end_session_endpoint ? String(obj.end_session_endpoint) : undefined,
  };
  if (!discovery.issuer || !discovery.authorization_endpoint || !discovery.token_endpoint || !discovery.jwks_uri) {
    throw new Error("Discovery document missing required fields");
  }
  // allow issuer without trailing slash normalization
  const normalizedIssuer = issuer.replace(/\/$/, "");
  if (discovery.issuer.replace(/\/$/, "") !== normalizedIssuer) {
    throw new Error(`Issuer mismatch. Expected ${normalizedIssuer} but discovery returned ${discovery.issuer}`);
  }
  discoveryCache.set(issuer, discovery);
  return discovery;
}

