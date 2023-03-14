import { HttpModule } from '@nestjs/axios';
import { Module } from '@nestjs/common';
import { TenantService } from './tenant.service';

@Module({
  imports: [HttpModule],
  providers: [TenantService],
  exports: [TenantService],
})
export class TenantModule {}
