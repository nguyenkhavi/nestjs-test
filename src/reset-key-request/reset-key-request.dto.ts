import { z } from 'zod';

import { createZodDto } from '@anatine/zod-nestjs';
import { extendApi } from '@anatine/zod-openapi';
import { ZMFACode, ZPassword } from 'src/utils/zod';

const ResetKey = z
  .object({
    tenantId: z.string().trim().nonempty(),
    domain: z.string().trim().nonempty(),
    projectId: z.string().trim().nonempty(),
  })
  .merge(ZPassword.required())
  .merge(ZMFACode);
export class ResetKeyDto extends createZodDto(extendApi(ResetKey)) {}

const VerifyResetKey = z.object({
  requestId: z.string().trim().nonempty(),
});
export class VerifyResetKeyDto extends createZodDto(
  extendApi(VerifyResetKey),
) {}

const VerifyResetKeySSO = z
  .object({
    requestId: z.string().trim().nonempty(),
    googleUid: z.string().optional(),
    facebookUid: z.string().optional(),
  })
  .refine((data) => !!data.googleUid || !!data.facebookUid, {
    message: 'One of googleUid and facebookUid must be provided!',
  });
export class VerifyResetKeySSODto extends createZodDto(
  extendApi(VerifyResetKeySSO),
) {}

const CheckRevealKey = z.object({
  projectId: z.string().trim().nonempty(),
});
export class CheckRevealKeyDto extends createZodDto(
  extendApi(CheckRevealKey),
) {}
