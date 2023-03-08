import { z } from 'zod';

import { createZodDto } from '@anatine/zod-nestjs';
import { extendApi } from '@anatine/zod-openapi';
import { ZPassword } from 'src/utils/zod';

const UserRegister = z
  .object({
    email: z.string().email('Email is invalid'),
  })
  .merge(ZPassword);
export class UserRegisterDto extends createZodDto(extendApi(UserRegister)) {}

const ConfirmEmail = z.object({
  token: z.string({
    required_error: 'Token is required',
  }),
});
export class ConfirmEmailDto extends createZodDto(extendApi(ConfirmEmail)) {}

const ResendConfirmEmail = z.object({
  email: z.string().email('Email is invalid'),
});
export class ResendConfirmEmailDto extends createZodDto(
  extendApi(ResendConfirmEmail),
) {}

const ForgotPassword = z.object({
  id: z.string().uuid('User id is invalid'),
});
export class ForgotPasswordDto extends createZodDto(
  extendApi(ForgotPassword),
) {}

const PutPassword = z
  .object({
    token: z.string({
      required_error: 'Token is required',
    }),
  })
  .merge(ZPassword);
export class PutPasswordDto extends createZodDto(extendApi(PutPassword)) {}

const Login = z
  .object({
    email: z.string().email('Email is invalid'),
    mfaCode: z.string().optional(),
  })
  .merge(ZPassword);
export class LoginDto extends createZodDto(extendApi(Login)) {}

const RefreshToken = z.object({
  refreshToken: z.string({
    required_error: 'Token is required',
  }),
});
export class RefreshTokenDto extends createZodDto(extendApi(RefreshToken)) {}
