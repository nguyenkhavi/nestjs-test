import { HttpModule } from '@nestjs/axios';
import { Module } from '@nestjs/common';
import { CustonomyService } from 'src/custonomy/custonomy.service';

@Module({
  imports: [HttpModule],
  exports: [CustonomyService],
  providers: [CustonomyService],
})
export class CustonomyModule {}
