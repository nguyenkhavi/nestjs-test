-- CreateEnum
CREATE TYPE "EMethod" AS ENUM ('AUTH_GENERATE', 'BRING_YOUR_OWN');

-- AlterTable
ALTER TABLE "user-tenant" ADD COLUMN     "method" "EMethod";
