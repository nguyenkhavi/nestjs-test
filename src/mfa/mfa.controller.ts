import { Body, Controller, Post, Request, UseGuards } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { JwtAuthGuard } from 'src/auth/jwt/jwt-auth.guard';
import { MFAVerifyDto } from 'src/mfa/mfa.dto';
import { MfaService } from './mfa.service';

@Controller('mfa')
@ApiTags('Multi-Factor Authentication')
export class MfaController {
  constructor(private readonly mfaService: MfaService) {}

  @Post('register')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'MFA - Generate Code',
    description: 'The code generated will be expired for 30 mins',
  })
  register(@Request() request) {
    const uid = request.user.uid;
    return this.mfaService.register(uid);
  }

  @Post('verify')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'MFA - Verify',
    description: 'The code generated will be expired for 30 mins',
  })
  verify(@Request() request, @Body() body: MFAVerifyDto) {
    const uid = request.user.uid;
    return this.mfaService.verify(uid, body);
  }

  @Post('disabled')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'MFA - Turn-off',
    description: 'Disabled Google Authenticator MFA',
  })
  disable(@Request() request) {
    const uid = request.user.uid;
    return this.mfaService.disable(uid);
  }
}
