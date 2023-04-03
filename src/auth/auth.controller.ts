import {
  Body,
  Controller,
  Get,
  Ip,
  Post,
  Put,
  UseGuards,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiOperation,
  ApiTags,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger';
import {
  ActiveMainnetTenantDto,
  ChangePasswordDto,
  ConfirmEmailDto,
  CreateMainnetTenantDto,
  ForgotPasswordDto,
  LoginDto,
  PutPasswordDto,
  RefreshTokenDto,
  ResendConfirmEmailDto,
  SecretShardDto,
  SSODto,
  UserRegisterDto,
  ValidatePasswordTokenDto,
  VerifyPasswordDto,
} from 'src/auth/auth.dto';
import { JwtAuthGuard } from 'src/auth/jwt/jwt-auth.guard';
import {
  Origin,
  Uid,
  UserAgent,
  Authorization,
  Session,
} from 'src/utils/decorators';
import { IUserAgent, TSession } from 'src/utils/interface';
import { AuthService } from './auth.service';

@Controller('auth')
@ApiTags('Auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Get('verify')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  verifyToken(@Uid() uid: string) {
    return this.authService.verifyToken(uid);
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

  @Put('validate-forgot-password-token')
  @ApiOperation({
    summary: 'Validate the token after forgot-password email sent',
  })
  validateForgotPasswordToken(@Body() body: ValidatePasswordTokenDto) {
    return this.authService.validateForgotPasswordToken(body);
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

  @Post('generate-secret-shard')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Generate secret shard',
  })
  generateSecretShard(
    @Body() body: SecretShardDto,
    // @Uid() uid: string,
  ) {
    return this.authService.generateSecretShard(body);
  }

  @Post('mainnet-tenant')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Create Mainnet Tenant',
  })
  upsertMainnetTenant(
    @Body() body: CreateMainnetTenantDto,
    @Uid() uid: string,
    @Authorization() authorization: string,
    @Session() session: TSession,
    @Ip() ip: string,
    @UserAgent() userAgent: IUserAgent,
    @Origin() origin: string,
  ) {
    return this.authService.upsertMainnetTenant(
      body,
      uid,
      authorization,
      session,
      {
        ip,
        userAgent,
        origin,
      },
    );
  }

  @Post('mainnet-tenant/send-again')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Resend email Active & Back-Up',
  })
  sendActiveBackUpAgain(
    @Uid() uid: string,
    @Ip() ip: string,
    @UserAgent() userAgent: IUserAgent,
    @Origin() origin: string,
  ) {
    return this.authService.sendActiveBackUpAgain(uid, {
      ip,
      userAgent,
      origin,
    });
  }

  @Post('active-mainnet-tenant')
  @ApiOperation({
    summary: 'Active Mainnet Tenant',
  })
  activeMainnetTenant(@Body() body: ActiveMainnetTenantDto) {
    return this.authService.activeMainnetTenant(body);
  }
}
