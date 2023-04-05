import { CacheModule, forwardRef, Module } from '@nestjs/common';
import { MfaService } from './mfa.service';
import { MfaController } from './mfa.controller';
import { PrismaModule } from 'src/prisma/prisma.module';
import { AuthModule } from 'src/auth/auth.module';
import { KmsModule } from 'src/kms/kms.module';

@Module({
  imports: [
    PrismaModule,
    forwardRef(() => AuthModule),
    CacheModule.register(),
    KmsModule,
  ],
  controllers: [MfaController],
  providers: [MfaService],
  exports: [MfaService],
})
export class MfaModule {}
