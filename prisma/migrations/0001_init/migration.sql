-- This file was generated via:
--   npx prisma migrate diff --from-empty --to-schema-datamodel prisma/schema.prisma --script
-- Apply using Prisma Migrate against your Postgres database.

-- CreateSchema
CREATE SCHEMA IF NOT EXISTS "public";

-- CreateTable
CREATE TABLE "TenantOidcConfig" (
    "tenantId" TEXT NOT NULL,
    "oktaIssuer" TEXT NOT NULL,
    "clientId" TEXT NOT NULL,
    "clientSecretEnc" TEXT NOT NULL,
    "scopes" TEXT NOT NULL DEFAULT 'openid profile email',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "TenantOidcConfig_pkey" PRIMARY KEY ("tenantId")
);

-- CreateTable
CREATE TABLE "LoginTransaction" (
    "state" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "nonce" TEXT NOT NULL,
    "codeVerifier" TEXT NOT NULL,
    "redirectTo" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "LoginTransaction_pkey" PRIMARY KEY ("state")
);

-- CreateTable
CREATE TABLE "Session" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "subject" TEXT NOT NULL,
    "claims" JSONB NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Session_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "LoginTransaction_tenantId_idx" ON "LoginTransaction"("tenantId");

-- CreateIndex
CREATE INDEX "LoginTransaction_createdAt_idx" ON "LoginTransaction"("createdAt");

-- CreateIndex
CREATE INDEX "Session_tenantId_idx" ON "Session"("tenantId");

-- CreateIndex
CREATE INDEX "Session_expiresAt_idx" ON "Session"("expiresAt");

-- AddForeignKey
ALTER TABLE "Session" ADD CONSTRAINT "Session_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "TenantOidcConfig"("tenantId") ON DELETE CASCADE ON UPDATE CASCADE;

