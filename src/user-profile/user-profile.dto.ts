import { z } from 'zod';

import { createZodDto } from '@anatine/zod-nestjs';
import { extendApi } from '@anatine/zod-openapi';

const UpdateUserProfile = z.object({
  name: z.string().optional(),
  avatar: z.string().optional(),
});

export class UpdateUserProfileDto extends createZodDto(
  extendApi(UpdateUserProfile),
) {}
