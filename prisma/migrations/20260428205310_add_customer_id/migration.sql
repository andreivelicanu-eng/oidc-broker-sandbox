-- AlterTable
ALTER TABLE "TenantOidcConfig" ADD COLUMN     "customerId" TEXT NOT NULL DEFAULT 'default';

-- CreateIndex
CREATE INDEX "TenantOidcConfig_customerId_idx" ON "TenantOidcConfig"("customerId");
