import { z } from 'zod';

import { createZodDto } from '@anatine/zod-nestjs';
import { extendApi } from '@anatine/zod-openapi';
import { EMode, EView } from 'src/proxy/proxy.interface';

const GetPreview = z.object({
  view: z.nativeEnum(EView),
  mode: z.nativeEnum(EMode),
  projectName: z.string().optional(),
  imageUrl: z.string().url().optional(),
  branding: z.string().optional(),
});
export class GetPreviewDto extends createZodDto(extendApi(GetPreview)) {}
