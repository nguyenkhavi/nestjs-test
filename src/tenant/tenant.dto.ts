import { z } from 'zod';

import { createZodDto } from '@anatine/zod-nestjs';
import { extendApi } from '@anatine/zod-openapi';
import { ZTimezone } from 'src/utils/zod';
const CreateTenant = z
  .object({
    token: z.string(),
    session: z.string(),
  })
  .merge(ZTimezone);
export class CreateTenantDto extends createZodDto(extendApi(CreateTenant)) {}
