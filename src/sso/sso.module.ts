import { Module } from '@nestjs/common';
import { SsoService } from './sso.service';

@Module({
  providers: [SsoService],
  exports: [SsoService],
})
export class SsoModule {}
