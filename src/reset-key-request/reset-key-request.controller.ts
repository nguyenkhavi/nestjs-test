import { Body, Controller, Post, UseGuards } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { JwtAuthGuard } from 'src/auth/jwt/jwt-auth.guard';
import {
  CheckRevealKeyDto,
  ResetKeyDto,
  VerifyResetKeyDto,
  VerifyResetKeySSODto,
} from 'src/reset-key-request/reset-key-request.dto';
import { ResetKeyRequestService } from 'src/reset-key-request/reset-key-request.service';
import { Authorization, Session, Uid } from 'src/utils/decorators';
import { TSession } from 'src/utils/interface';

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
    @Session() session: TSession,
    @Authorization() auth: string,
  ) {
    return this.resetKeyRequestService.resetKey(dto, uid, session, auth);
  }

  @Post('check-reveal-key')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Check weather user can reveal key or not',
  })
  checkRevealKey(@Body() dto: CheckRevealKeyDto, @Uid() uid: string) {
    return this.resetKeyRequestService.checkRevealKey(dto, uid);
  }

  @Post('verify-reset-key')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Verify reset key request with local-login user',
  })
  verifyResetKey(@Body() dto: VerifyResetKeyDto, @Uid() uid: string) {
    return this.resetKeyRequestService.verifyResetKey(dto, uid);
  }

  @Post('verify-reset-key-sso')
  @ApiOperation({
    summary: 'Verify reset key request with SSO user',
  })
  verifyResetKeySSO(@Body() dto: VerifyResetKeySSODto) {
    return this.resetKeyRequestService.verifyResetKeyByProvider(dto);
  }
}
