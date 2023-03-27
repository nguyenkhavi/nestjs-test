/*
  Warnings:

  - Added the required column `custonomyUserId` to the `user-tenant` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE "user-tenant" ADD COLUMN     "custonomyUserId" TEXT NOT NULL;
