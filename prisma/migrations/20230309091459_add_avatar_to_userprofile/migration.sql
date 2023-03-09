/*
  Warnings:

  - A unique constraint covering the columns `[userId]` on the table `user-profile` will be added. If there are existing duplicate values, this will fail.

*/
-- AlterTable
ALTER TABLE "user-profile" ADD COLUMN     "avatar" VARCHAR(255) NOT NULL DEFAULT '',
ALTER COLUMN "name" SET DEFAULT '';

-- CreateIndex
CREATE UNIQUE INDEX "user-profile_userId_key" ON "user-profile"("userId");
