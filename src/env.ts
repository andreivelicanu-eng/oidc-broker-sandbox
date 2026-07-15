import { z } from "zod";

function emptyToUndefined(v: unknown) {
  if (v === undefined || v === null) return undefined;
  if (typeof v === "string" && v.trim() === "") return undefined;
  return v;
}

const EnvSchema = z
  .object({
    DATABASE_URL: z.string().min(1),
    PUBLIC_BASE_URL: z.string().url(),
    ADMIN_API_KEY: z.string().min(12),
    TENANT_SECRET_ENCRYPTION_KEY: z.string().min(20),
    SESSION_SIGNING_KEY: z.string().min(20),
    COOKIE_SECURE: z.enum(["true", "false"]).default("false"),
    PORT: z.coerce.number().int().positive().default(4010),
    /** e.g. `dev-xxx.eu.auth0.com` (no scheme). Required with AUTH0_CLIENT_ID and AUTH0_CLIENT_SECRET for Auth0 admin login. */
    AUTH0_DOMAIN: z.preprocess(emptyToUndefined, z.string().min(3).optional()),
    AUTH0_CLIENT_ID: z.preprocess(emptyToUndefined, z.string().min(1).optional()),
    AUTH0_CLIENT_SECRET: z.preprocess(emptyToUndefined, z.string().min(1).optional()),
    /** Comma-separated emails allowed to complete Auth0 admin login. If unset, any Auth0 user who completes login receives an admin session (use only for demos). */
    ADMIN_AUTH0_ALLOWED_EMAILS: z.preprocess(emptyToUndefined, z.string().optional()),
    /** JWT claim name for broker workspace / customerId (e.g. `https://backupta.com/workspace`). If missing, workspace is `default`. */
    AUTH0_WORKSPACE_CLAIM: z.preprocess(emptyToUndefined, z.string().min(1).optional()),
    /**
     * Optional full OAuth callback URL registered in Auth0 (must match exactly).
     * Use when PUBLIC_BASE_URL or the browser URL differs from what Auth0 should see (e.g. Fly internal URL vs public hostname).
     */
    AUTH0_REDIRECT_URI: z.preprocess(emptyToUndefined, z.string().url().optional()),
  })
  .superRefine((data, ctx) => {
    const trio = [data.AUTH0_DOMAIN, data.AUTH0_CLIENT_ID, data.AUTH0_CLIENT_SECRET];
    const all = trio.every(Boolean);
    const any = trio.some(Boolean);
    if (any && !all) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message:
          "Set all of AUTH0_DOMAIN, AUTH0_CLIENT_ID, and AUTH0_CLIENT_SECRET to enable Auth0 admin login, or omit all three.",
        path: ["AUTH0_DOMAIN"],
      });
    }
  });

export type Env = z.infer<typeof EnvSchema>;

export function getEnv(): Env {
  const parsed = EnvSchema.safeParse(process.env);
  if (!parsed.success) {
    const message = parsed.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("\n");
    throw new Error(`Invalid environment:\n${message}`);
  }
  return parsed.data;
}

