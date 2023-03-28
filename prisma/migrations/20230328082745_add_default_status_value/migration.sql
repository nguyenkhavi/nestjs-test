-- This is an empty migration.
UPDATE "user-tenant" SET "status" = 'ACTIVE' WHERE "status" IS NULL;