import { Body, Controller, Post, UseGuards } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { JwtAuthGuard } from 'src/auth/jwt/jwt-auth.guard';
import {
  ResetKeyDto,
  VerifyResetKeyDto,
} from 'src/reset-key-request/reset-key-request.dto';
import { ResetKeyRequestService } from 'src/reset-key-request/reset-key-request.service';
import { Authorization, Session, Uid } from 'src/utils/decorators';

@Controller('reset-key-request')
@ApiTags('Reset Keys Request')
export class ResetKeyRequestController {
  constructor(
    private readonly resetKeyRequestService: ResetKeyRequestService,
  ) {}
  @Post('reset-key')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Reset key for a project',
  })
  resetKey(
    @Body() dto: ResetKeyDto,
    @Uid() uid: string,
    @Session() session: string,
    @Authorization() auth: string,
  ) {
    return this.resetKeyRequestService.resetKey(dto, uid, session, auth);
  }

  @Post('verify-reset-key')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Verify reset key request for a project',
  })
  verifyResetKey(@Body() dto: VerifyResetKeyDto, @Uid() uid: string) {
    return this.resetKeyRequestService.verifyResetKey(dto, uid);
  }
}
