import { z } from 'zod';

export const ZPassword = z.object({
  password: z
    .string()
    .trim()
    .min(8, 'Password must be at least 8 characters long')
    .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
    .regex(/[a-z]/, 'Password must contain at least one lowercase letter')
    .regex(
      /[!@#$%^&*()_+[\]{};':"\\|,.<>/?-]/,
      'Password must contain at least one special letter',
    ),
});

export const ZMFACode = z.object({
  mfaCode: z.string().trim().length(6, 'MFA Code format is invalid').optional(),
});
