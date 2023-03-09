-- CreateTable
CREATE TABLE "user-profile" (
    "id" TEXT NOT NULL,
    "userId" UUID NOT NULL,
    "name" VARCHAR(255) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "user-profile_pkey" PRIMARY KEY ("id")
);
