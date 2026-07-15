# oidc-broker (multi-tenant Okta OIDC)

This is a small **multi-tenant Okta OIDC login service**. Each tenant corresponds to a separate Okta issuer + OIDC app integration.

## Local setup

- Start Postgres:

```bash
cd oidc-broker
docker compose up -d
```

- Install deps and run migrations:

```bash
npm install
npm run prisma:migrate
```

- Create `.env`:

```bash
cp .env.example .env
```

Generate 32-byte base64 keys:

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"
```

Set:
- `TENANT_SECRET_ENCRYPTION_KEY` = (base64 32 bytes)
- `SESSION_SIGNING_KEY` = (base64 32 bytes)
- `ADMIN_API_KEY` = long random string

- Run dev server:

```bash
npm run dev
```

## Okta setup (per tenant)

In each Okta tenant:
- Create an **OIDC app integration** (Web / confidential client).
- Add redirect URI: `{PUBLIC_BASE_URL}/oidc/callback`
- Copy:
  - **Issuer** (example): `https://dev-123456.okta.com/oauth2/default`
  - **Client ID**
  - **Client secret**

## Onboard a tenant

### Using the built-in admin UI

Open:
- `{PUBLIC_BASE_URL}/admin/ui`

Paste your `ADMIN_API_KEY` and the Okta tenant settings, then submit.

### Listing configured tenants (browser)

Open:
- `{PUBLIC_BASE_URL}/admin/tenants`

### Using curl

```bash
curl -sS -X POST "http://localhost:4010/admin/tenants" \
  -H "content-type: application/json" \
  -H "x-admin-key: $ADMIN_API_KEY" \
  -d '{
    "tenantId": "acme",
    "oktaIssuer": "https://dev-123456.okta.com/oauth2/default",
    "clientId": "YOUR_CLIENT_ID",
    "clientSecret": "YOUR_CLIENT_SECRET",
    "scopes": "openid profile email"
  }'
```

## Deploy to Fly.io

From `oidc-broker/`:

```bash
fly launch
fly postgres create
fly postgres attach --app <your-app-name> <your-postgres-name>
fly secrets set \
  PUBLIC_BASE_URL="https://<your-app-name>.fly.dev" \
  ADMIN_API_KEY="..." \
  TENANT_SECRET_ENCRYPTION_KEY="..." \
  SESSION_SIGNING_KEY="..."
fly deploy
```

Notes:
- Fly runs `npx prisma migrate deploy` automatically during deploy (see `fly.toml`).
- After going live, make sure each Okta OIDC app has redirect URI `https://<your-app-name>.fly.dev/oidc/callback`.

## Deploy to Vercel (+ Neon Postgres)

This app runs on Vercel as a single serverless function that wraps the Express
app (`api/index.ts` re-exports the built app from `dist/`). All routes are
rewritten to that function via `vercel.json`, while files in `public/` are served
statically (so `/admin-assets/*` works unchanged).

### 1. Create a Neon database

1. Create a project at [neon.tech](https://neon.tech) (free tier).
2. Grab **two** connection strings from the dashboard:
   - **Pooled** (host contains `-pooler`) → use for `DATABASE_URL`.
   - **Direct** (no `-pooler`) → use for `DIRECT_URL` (used by migrations).
   - Both must include `?sslmode=require`.

### 2. Import the project into Vercel

- New Project → import this repo/folder. Framework preset: **Other** (the
  included `vercel.json` already sets the build + run commands).
- The build runs: `prisma generate && prisma migrate deploy && npm run build`,
  so your schema is migrated onto Neon during deploy.

### 3. Set environment variables (Vercel → Project → Settings → Environment Variables)

```
DATABASE_URL   = <neon POOLED url, sslmode=require>
DIRECT_URL     = <neon DIRECT url, sslmode=require>
PUBLIC_BASE_URL= https://<your-vercel-domain-or-custom-domain>
ADMIN_API_KEY  = <long random string>
TENANT_SECRET_ENCRYPTION_KEY = <base64 32 bytes>
SESSION_SIGNING_KEY          = <base64 32 bytes>
COOKIE_SECURE  = true
```

(Optional Auth0 admin login: also set `AUTH0_DOMAIN`, `AUTH0_CLIENT_ID`,
`AUTH0_CLIENT_SECRET`, and `AUTH0_REDIRECT_URI=https://<domain>/admin/auth/auth0/callback`.)

Then **Deploy**.

### 4. Add a custom domain

1. Vercel → Project → **Settings → Domains** → add e.g. `broker.yourdomain.com`.
2. At your DNS provider, add the record Vercel shows:
   - Subdomain → **CNAME** to `cname.vercel-dns.com`.
   - Apex/root → **A** record to Vercel's IP (or an ALIAS/ANAME if supported).
3. Vercel provisions SSL automatically.
4. Update `PUBLIC_BASE_URL` to the custom domain and redeploy.
5. In **each Okta/Auth0** app, set the redirect URI to
   `https://<custom-domain>/oidc/callback` (and the Auth0 callback/logout URLs).

Notes:
- Prisma on serverless requires the **pooled** `DATABASE_URL`; using a direct URL
  will exhaust connections under load.
- Sessions and login transactions are stored in Postgres, so no server memory
  state is needed between requests.

## Start login

Visit:
- `http://localhost:4010/t/acme/login?redirectTo=/`

After login, call:
- `http://localhost:4010/t/acme/me`

## Endpoints

- `POST /admin/tenants` (requires `x-admin-key`)
- `GET /t/:tenantId/login`
- `GET /oidc/callback`
- `GET /t/:tenantId/me`
- `POST /t/:tenantId/logout`
- `GET /healthz`

## Notes

- `redirectTo` only allows **relative paths**.
- Uses PKCE + state + nonce.
- Uses per-issuer discovery and JWKS via `jose`.

