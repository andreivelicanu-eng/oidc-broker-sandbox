-- CreateTable
CREATE TABLE "TenantSamlConfig" (
    "tenantId" TEXT NOT NULL,
    "customerId" TEXT NOT NULL DEFAULT 'default',
    "idpEntityId" TEXT NOT NULL,
    "idpSsoUrl" TEXT NOT NULL,
    "idpCert" TEXT NOT NULL,
    "spEntityId" TEXT NOT NULL,
    "acsUrl" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "TenantSamlConfig_pkey" PRIMARY KEY ("tenantId")
);

-- CreateTable
CREATE TABLE "SamlLoginTransaction" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "redirectTo" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "SamlLoginTransaction_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "TenantSamlConfig_customerId_idx" ON "TenantSamlConfig"("customerId");

-- CreateIndex
CREATE INDEX "SamlLoginTransaction_tenantId_idx" ON "SamlLoginTransaction"("tenantId");

-- CreateIndex
CREATE INDEX "SamlLoginTransaction_createdAt_idx" ON "SamlLoginTransaction"("createdAt");
