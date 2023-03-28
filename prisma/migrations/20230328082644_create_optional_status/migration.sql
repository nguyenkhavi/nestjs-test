-- CreateEnum
CREATE TYPE "ETenantStatus" AS ENUM ('ACTIVE', 'INACTIVE');

-- AlterTable
ALTER TABLE "user-tenant" ADD COLUMN     "status" "ETenantStatus";
