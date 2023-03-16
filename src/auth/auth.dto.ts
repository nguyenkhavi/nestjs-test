import { z } from 'zod';

import { createZodDto } from '@anatine/zod-nestjs';
import { extendApi } from '@anatine/zod-openapi';
import { ZMFACode, ZPassword, ZTimezone } from 'src/utils/zod';

const UserRegister = z
  .object({
    email: z.string().trim().toLowerCase().email('Email is invalid'),
  })
  .merge(ZPassword.required())
  .merge(ZTimezone.required());
export class UserRegisterDto extends createZodDto(extendApi(UserRegister)) {}

const ConfirmEmail = z.object({
  token: z.string({
    required_error: 'Token is required',
  }),
});
export class ConfirmEmailDto extends createZodDto(extendApi(ConfirmEmail)) {}

const ResendConfirmEmail = z.object({
  email: z.string().trim().toLowerCase().email('Email is invalid'),
});
export class ResendConfirmEmailDto extends createZodDto(
  extendApi(ResendConfirmEmail),
) {}

const ForgotPassword = z.object({
  email: z.string().trim().toLowerCase().email('Email is invalid'),
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

const VerifyPassword = z.object({}).merge(ZPassword).merge(ZMFACode);
export class VerifyPasswordDto extends createZodDto(
  extendApi(VerifyPassword),
) {}

const ChangePassword = z
  .object({
    newPassword: ZPassword.pick({ password: true }),
  })
  .merge(ZPassword)
  .merge(ZMFACode);
export class ChangePasswordDto extends createZodDto(
  extendApi(ChangePassword),
) {}

const Login = z
  .object({
    email: z.string().trim().toLowerCase().email('Email is invalid'),
  })
  .merge(ZPassword)
  .merge(ZMFACode);
export class LoginDto extends createZodDto(extendApi(Login)) {}

const RefreshToken = z.object({
  refreshToken: z.string({
    required_error: 'Token is required',
  }),
});
export class RefreshTokenDto extends createZodDto(extendApi(RefreshToken)) {}

const SSO = z
  .object({
    token: z.string({
      required_error: 'Token is required',
    }),
  })
  .merge(ZMFACode)
  .merge(ZTimezone.required());
export class SSODto extends createZodDto(extendApi(SSO)) {}
