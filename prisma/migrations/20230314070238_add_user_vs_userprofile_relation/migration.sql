-- AddForeignKey
ALTER TABLE "user-profile" ADD CONSTRAINT "user-profile_userId_fkey" FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
