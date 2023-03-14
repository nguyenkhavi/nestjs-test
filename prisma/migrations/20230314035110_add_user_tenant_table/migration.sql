-- CreateEnum
CREATE TYPE "EEnviroment" AS ENUM ('MAINNET', 'TESTNET');

-- CreateTable
CREATE TABLE "user-tenant" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "signNodeId" TEXT NOT NULL,
    "env" "EEnviroment" NOT NULL DEFAULT 'TESTNET',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "user-tenant_pkey" PRIMARY KEY ("id")
);

-- AddForeignKey
ALTER TABLE "user-tenant" ADD CONSTRAINT "user-tenant_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
