/*
  Warnings:

  - Added the required column `projectId` to the `reset-key-request` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE "reset-key-request" ADD COLUMN     "projectId" TEXT NOT NULL;
