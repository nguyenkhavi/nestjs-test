import { Body, Controller, Ip, Post, Put } from '@nestjs/common';
import {
  ApiForbiddenResponse,
  ApiOperation,
  ApiTags,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger';
import {
  ConfirmEmailDto,
  ForgotPasswordDto,
  LoginDto,
  PutPasswordDto,
  RefreshTokenDto,
  ResendConfirmEmailDto,
  UserRegisterDto,
} from 'src/auth/auth.dto';
import { Origin, UserAgent } from 'src/utils/decorators';
import { IUserAgent } from 'src/utils/interface';
import { AuthService } from './auth.service';

@Controller('auth')
@ApiTags('Auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

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

  @Post('login')
  @ApiOperation({
    summary: 'Login',
    description:
      'Field `mfaCode` is required in case user enabled Google Authenticator',
  })
  @ApiForbiddenResponse({
    description:
      'Client need to redirect to MFA Code page and submit both email, password and MFA Code again',
  })
  @ApiUnauthorizedResponse({
    description: 'Credential provided is invalid',
  })
  login(@Body() body: LoginDto) {
    return this.authService.login(body);
  }

  @Post('refresh-token')
  @ApiOperation({
    summary: 'Get new `accessToken` based on `refreshToken` provided',
  })
  refreshToken(@Body() body: RefreshTokenDto) {
    return this.authService.refreshToken(body);
  }
}
