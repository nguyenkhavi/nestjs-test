import { Body, Controller, Post, Put } from '@nestjs/common';
import { ApiOperation, ApiTags } from '@nestjs/swagger';
import {
  ConfirmEmailDto,
  ForgotPasswordDto,
  PutPasswordDto,
  ResendConfirmEmailDto,
  UserRegisterDto,
} from 'src/auth/auth.dto';
import { AuthService } from './auth.service';

@Controller('auth')
@ApiTags('Auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  @ApiOperation({
    summary: 'Sign up/Register purpose',
    description:
      'Password must have at least 8 chars, contain both lowercase and uppercase',
  })
  register(@Body() body: UserRegisterDto) {
    return this.authService.register(body);
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
  resendConfirmEmail(@Body() body: ResendConfirmEmailDto) {
    return this.authService.resendConfirmEmail(body);
  }

  @Post('forgot-password')
  @ApiOperation({
    summary: 'Trigger send forgot-password email',
  })
  forgotPassword(@Body() body: ForgotPasswordDto) {
    return this.authService.forgotPassword(body);
  }

  @Put('put-password')
  @ApiOperation({
    summary: 'Set new password after forgot-password email sent',
  })
  putPassword(@Body() body: PutPasswordDto) {
    return this.authService.putPassword(body);
  }
}
