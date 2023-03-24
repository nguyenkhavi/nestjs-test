import { HttpService } from '@nestjs/axios';
import {
  BadRequestException,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { firstValueFrom } from 'rxjs';
import * as dayjs from 'dayjs';
import { AuthService } from 'src/auth/auth.service';
import { ConfigService } from 'src/config/config.service';
import { PrismaService } from 'src/prisma/prisma.service';
import {
  CheckRevealKeyDto,
  ResetKeyDto,
  VerifyResetKeyDto,
  VerifyResetKeySSODto,
} from 'src/reset-key-request/reset-key-request.dto';
import { TenantService } from 'src/tenant/tenant.service';
import { _5MIN_MILLISECONDS_ } from 'src/utils/constants';
import { ERequestStatus } from '@prisma/client';

@Injectable()
export class ResetKeyRequestService {
  constructor(
    private readonly prismaService: PrismaService,
    private readonly authService: AuthService,
    private readonly tenantService: TenantService,
    private readonly httpService: HttpService,
    private readonly configService: ConfigService,
  ) {}
  async resetKey(
    dto: ResetKeyDto,
    userId: string,
    session: string,
    auth: string,
  ) {
    const { mfaCode, password, projectId, tenantId, domain } = dto;
    const { data: verifiedData } = await this.authService.checkPassword2FA(
      userId,
      password,
      mfaCode,
    );

    if (verifiedData.mfaRequired) {
      return {
        data: verifiedData,
      };
    }
    const { BASE_URL, API_KEY } = await this.tenantService.validateTenantId(
      tenantId,
      userId,
    );
    const request = await this.prismaService.resetKeyRequest.create({
      data: {
        projectId,
        userId,
      },
    });
    const requestId = request.id;

    try {
      const { data } = await firstValueFrom(
        this.httpService.request({
          baseURL: BASE_URL,
          method: 'POST',
          url: `v0/${tenantId}/${domain}/projects/${projectId}/accessKey`,
          headers: {
            'api-key': API_KEY,
            Authorization: auth,
            session,
            requestId,
          },
        }),
      );
      await this.prismaService.resetKeyRequest.update({
        where: {
          id: requestId,
        },
        data: { status: ERequestStatus.SUCCESS },
      });
      return { data };
    } catch (e) {
      await this.prismaService.resetKeyRequest.update({
        where: {
          id: requestId,
        },
        data: { status: ERequestStatus.ERROR },
      });
      throw e;
    }
  }

  async verifyResetKey(dto: VerifyResetKeyDto, userId: string) {
    const { requestId } = dto;
    const request = await this.prismaService.resetKeyRequest.findUniqueOrThrow({
      where: {
        id: requestId,
      },
    });
    if (request.userId !== userId) {
      throw new ForbiddenException('The request is own by another user!');
    }

    const expired =
      dayjs().diff(dayjs(request.createdAt), 'milliseconds') >=
      _5MIN_MILLISECONDS_;
    if (expired) {
      throw new BadRequestException('Request is expired!');
    }

    return { data: { success: true } };
  }

  async verifyResetKeyByProvider(dto: VerifyResetKeySSODto) {
    const { requestId, googleUid, facebookUid } = dto;
    const request = await this.prismaService.resetKeyRequest.findUniqueOrThrow({
      where: {
        id: requestId,
      },
      include: {
        user: true,
      },
    });
    const user = request.user;
    if (user.googleUid !== googleUid && !!googleUid) {
      throw new ForbiddenException('The request is own by another user!');
    }

    if (user.facebookUid !== facebookUid && !!facebookUid) {
      throw new ForbiddenException('The request is own by another user!');
    }

    const expired =
      dayjs().diff(dayjs(request.createdAt), 'milliseconds') >=
      _5MIN_MILLISECONDS_;
    if (expired) {
      throw new BadRequestException('Request is expired!');
    }

    return { data: { success: true } };
  }

  async checkRevealKey(dto: CheckRevealKeyDto, userId: string) {
    const { projectId } = dto;
    const request = await this.prismaService.resetKeyRequest.findFirst({
      where: {
        userId,
        projectId,
        status: ERequestStatus.SUCCESS,
      },
    });
    return {
      data: { request, canRevealKey: !request },
    };
  }
}
