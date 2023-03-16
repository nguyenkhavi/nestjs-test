import { Module } from '@nestjs/common';
import { ResetKeyRequestService } from './reset-key-request.service';
import { ResetKeyRequestController } from './reset-key-request.controller';
import { PrismaModule } from 'src/prisma/prisma.module';
import { AuthModule } from 'src/auth/auth.module';
import { TenantModule } from 'src/tenant/tenant.module';
import { HttpModule } from '@nestjs/axios';

@Module({
  imports: [PrismaModule, AuthModule, TenantModule, HttpModule],
  providers: [ResetKeyRequestService],
  controllers: [ResetKeyRequestController],
})
export class ResetKeyRequestModule {}
