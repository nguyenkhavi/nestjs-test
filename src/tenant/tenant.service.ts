import { HttpService } from '@nestjs/axios';
import { Injectable } from '@nestjs/common';
import { EEnviroment, UserTenant } from '@prisma/client';
import { firstValueFrom } from 'rxjs';
import { ConfigService } from 'src/config/config.service';
import { PrismaService } from 'src/prisma/prisma.service';
import { CreateTenantDto } from 'src/tenant/tenant.dto';

@Injectable()
export class TenantService {
  constructor(
    private readonly httpService: HttpService,
    private readonly configService: ConfigService,
    private readonly prismaService: PrismaService,
  ) {}
  async createTestnetTenant(dto: CreateTenantDto) {
    const { token, timezone, session } = dto;
    const { data } = await firstValueFrom(
      this.httpService.request<
        Pick<UserTenant, 'signNodeId' | 'tenantId'> & { userId: string }
      >({
        baseURL: this.configService.get('proxy.testnetUrl'),
        method: 'POST',
        url: 'v0/tenants',
        headers: {
          'api-key': this.configService.get('proxy.testnetApiKey'),
          Authorization: `Bearer ${token}`,
          session,
        },
        data: {
          timezone,
        },
      }),
    );
    return data;
  }

  async validateTenantId(tenantId: string, userId: string) {
    const tenant = await this.prismaService.userTenant.findFirstOrThrow({
      where: {
        userId,
        tenantId,
      },
    });
    const ENV_MAP = {
      [EEnviroment.TESTNET]: {
        BASE_URL: this.configService.get('proxy.testnetUrl'),
        API_KEY: this.configService.get('proxy.testnetApiKey'),
      },
      [EEnviroment.MAINNET]: {
        BASE_URL: this.configService.get('proxy.mainnetUrl'),
        API_KEY: this.configService.get('proxy.mainnetApiKey'),
      },
    };
    const env = tenant.env;
    return ENV_MAP[env];
  }
}
