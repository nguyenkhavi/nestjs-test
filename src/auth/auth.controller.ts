import {
  Body,
  Controller,
  Head,
  Ip,
  Post,
  Put,
  Response,
  UseGuards,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiOperation,
  ApiTags,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger';
import {
  ChangePasswordDto,
  ConfirmEmailDto,
  ForgotPasswordDto,
  LoginDto,
  PutPasswordDto,
  RefreshTokenDto,
  ResendConfirmEmailDto,
  SSODto,
  UserRegisterDto,
  VerifyPasswordDto,
} from 'src/auth/auth.dto';
import { JwtAuthGuard } from 'src/auth/jwt/jwt-auth.guard';
import { Origin, Uid, UserAgent } from 'src/utils/decorators';
import { IUserAgent } from 'src/utils/interface';
import { AuthService } from './auth.service';

@Controller('auth')
@ApiTags('Auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Head('verify')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  async verifyToken(@Response() response, @Uid() uid: string) {
    await response.append('uid', uid);
    await response.sendStatus(200);
  }

  @Post('register')
  @ApiOperation({
    summary: 'Sign up/Register purpose',
    description:
      'Password must have at least 8 chars, contain both special letter, lowercase and uppercase',
  })
  register(
    @Body() body: UserRegisterDto,
    @Ip() ip: string,
    @UserAgent() userAgent: IUserAgent,
    @Origin() origin: string,
  ) {
    return this.authService.register(body, { ip, userAgent, origin });
  }

  @Post('confirm-email')
  @ApiOperation({
    summary: 'Confirm email',
    description: 'Confirm email after user signed up',
  })
  confirmEmail(@Body() body: ConfirmEmailDto) {
    return this.authService.confirmEmail(body);
  }

  @Post('resend-confirm-email')
  @ApiOperation({
    summary: 'Resend confirm email',
    description: 'Confirm email after user signed up',
  })
  resendConfirmEmail(
    @Body() body: ResendConfirmEmailDto,
    @Ip() ip: string,
    @UserAgent() userAgent: IUserAgent,
    @Origin() origin: string,
  ) {
    return this.authService.resendConfirmEmail(body, { ip, userAgent, origin });
  }

  @Post('forgot-password')
  @ApiOperation({
    summary: 'Trigger send forgot-password email',
  })
  forgotPassword(
    @Body() body: ForgotPasswordDto,
    @Ip() ip: string,
    @UserAgent() userAgent: IUserAgent,
    @Origin() origin: string,
  ) {
    return this.authService.forgotPassword(body, { ip, userAgent, origin });
  }

  @Put('put-password')
  @ApiOperation({
    summary: 'Set new password after forgot-password email sent',
  })
  putPassword(@Body() body: PutPasswordDto) {
    return this.authService.putPassword(body);
  }

  @Post('verify-password')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Verify password',
  })
  verifyPassword(@Body() body: VerifyPasswordDto, @Uid() uid: string) {
    return this.authService.verifyPassword(uid, body);
  }

  @Post('change-password')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Change password',
  })
  changePassword(@Body() body: ChangePasswordDto, @Uid() uid: string) {
    return this.authService.changePassword(uid, body);
  }

  @Post('login')
  @ApiOperation({
    summary: 'Login',
    description:
      'Field `mfaCode` is required in case user enabled Google Authenticator',
  })
  @ApiUnauthorizedResponse({
    description: 'Credential provided is invalid',
  })
  login(@Body() body: LoginDto) {
    return this.authService.login(body);
  }

  @Post('sso/google')
  @ApiOperation({
    summary: 'Google SSO',
    description:
      'Field `mfaCode` is required in case user enabled Google Authenticator',
  })
  @ApiUnauthorizedResponse({
    description: 'Credential provided is invalid',
  })
  ssoGoogle(@Body() body: SSODto) {
    return this.authService.ssoGoogle(body);
  }

  @Post('sso/facebook')
  @ApiOperation({
    summary: 'Facebook SSO',
    description:
      'Field `mfaCode` is required in case user enabled Google Authenticator',
  })
  @ApiUnauthorizedResponse({
    description: 'Credential provided is invalid',
  })
  ssoFacebook(@Body() body: SSODto) {
    return this.authService.ssoFacebook(body);
  }

  @Post('refresh-token')
  @ApiOperation({
    summary: 'Get new `accessToken` based on `refreshToken` provided',
  })
  refreshToken(@Body() body: RefreshTokenDto) {
    return this.authService.refreshToken(body);
  }
}
