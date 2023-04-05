import { HttpModule } from '@nestjs/axios';
import { CacheModule, Module } from '@nestjs/common';
import { PrismaModule } from 'src/prisma/prisma.module';
import { TenantService } from './tenant.service';

@Module({
  imports: [HttpModule, PrismaModule, CacheModule.register()],
  providers: [TenantService],
  exports: [TenantService],
})
export class TenantModule {}
