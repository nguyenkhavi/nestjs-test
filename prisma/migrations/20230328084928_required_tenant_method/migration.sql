-- This is an empty migration.
UPDATE "user-tenant" SET "method" = 'AUTO_GENERATE' WHERE "method" IS NULL;

ALTER TABLE "user-tenant" ALTER COLUMN "method" SET NOT NULL;