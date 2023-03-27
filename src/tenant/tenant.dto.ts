import { z } from 'zod';

import { createZodDto } from '@anatine/zod-nestjs';
import { extendApi } from '@anatine/zod-openapi';
import { ZTimezone } from 'src/utils/zod';
import { TSession } from 'src/utils/interface';
const CreateTenant = z
  .object({
    session: z.string(),
  })
  .merge(ZTimezone);
export class CreateTenantDto extends createZodDto(extendApi(CreateTenant)) {
  session: TSession;
}
