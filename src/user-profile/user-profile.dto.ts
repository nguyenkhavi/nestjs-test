import { z } from 'zod';

import { createZodDto } from '@anatine/zod-nestjs';
import { extendApi } from '@anatine/zod-openapi';

const UpdateUserProfile = z.object({
  name: z.string().trim().max(50, `The limit is 50 characters.`).optional(),
  avatar: z.string().trim().optional(),
});

export class UpdateUserProfileDto extends createZodDto(
  extendApi(UpdateUserProfile),
) {}
