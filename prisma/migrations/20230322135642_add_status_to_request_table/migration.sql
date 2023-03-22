-- CreateEnum
CREATE TYPE "ERequestStatus" AS ENUM ('PENDING', 'SUCCESS', 'ERROR');

-- AlterTable
ALTER TABLE "reset-key-request" ADD COLUMN     "status" "ERequestStatus" NOT NULL DEFAULT 'PENDING';
