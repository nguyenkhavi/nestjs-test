import { z } from 'zod';

import { createZodDto } from '@anatine/zod-nestjs';
import { extendApi } from '@anatine/zod-openapi';

const UserRegister = z.object({
  email: z.string().email('Email is invalid'),
  password: z
    .string()
    .min(8, 'Password must be at least 8 characters long')
    .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
    .regex(/[a-z]/, 'Password must contain at least one lowercase letter'),
});
export class UserRegisterDto extends createZodDto(extendApi(UserRegister)) {}

const ConfirmEmail = z.object({
  token: z.string({
    required_error: 'Token is required',
  }),
});
export class ConfirmEmailDto extends createZodDto(extendApi(ConfirmEmail)) {}

const ResendConfirmEmail = z.object({
  id: z.string().uuid('User id is invalid'),
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

const PutPassword = z.object({
  token: z.string({
    required_error: 'Token is required',
  }),
  password: z
    .string()
    .min(8, 'Password must be at least 8 characters long')
    .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
    .regex(/[a-z]/, 'Password must contain at least one lowercase letter'),
});
export class PutPasswordDto extends createZodDto(extendApi(PutPassword)) {}
