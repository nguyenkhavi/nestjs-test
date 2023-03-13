-- CreateEnum
CREATE TYPE "EUserStatus" AS ENUM ('ACTIVE', 'INACTIVE');

-- AlterTable
ALTER TABLE "user" ADD COLUMN     "status" "EUserStatus" NOT NULL DEFAULT 'ACTIVE';
