/*
  Warnings:

  - The values [AUTH_GENERATE] on the enum `EMethod` will be removed. If these variants are still used in the database, this will fail.

*/
-- AlterEnum
BEGIN;
CREATE TYPE "EMethod_new" AS ENUM ('AUTO_GENERATE', 'BRING_YOUR_OWN');
ALTER TABLE "user-tenant" ALTER COLUMN "method" TYPE "EMethod_new" USING ("method"::text::"EMethod_new");
ALTER TYPE "EMethod" RENAME TO "EMethod_old";
ALTER TYPE "EMethod_new" RENAME TO "EMethod";
DROP TYPE "EMethod_old";
COMMIT;
