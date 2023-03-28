/*
  Warnings:

  - Made the column `status` on table `user-tenant` required. This step will fail if there are existing NULL values in that column.

*/
-- AlterTable
ALTER TABLE "user-tenant" ALTER COLUMN "status" SET NOT NULL;
