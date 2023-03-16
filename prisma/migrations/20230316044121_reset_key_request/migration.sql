-- CreateTable
CREATE TABLE "reset-key-request" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "reset-key-request_pkey" PRIMARY KEY ("id")
);

-- AddForeignKey
ALTER TABLE "reset-key-request" ADD CONSTRAINT "reset-key-request_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
