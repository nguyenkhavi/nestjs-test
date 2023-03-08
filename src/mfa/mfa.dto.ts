import { createZodDto } from '@anatine/zod-nestjs';
import { ZMFACode } from 'src/utils/zod';
import { z } from 'zod';
import { extendApi } from '@anatine/zod-openapi';

const MFAVerify = z.object({}).merge(ZMFACode.required());
export class MFAVerifyDto extends createZodDto(extendApi(MFAVerify)) {}
