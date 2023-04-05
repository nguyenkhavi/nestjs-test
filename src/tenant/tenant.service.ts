import { CACHE_MANAGER, Inject, Injectable } from '@nestjs/common';
import { EEnviroment, UserTenant } from '@prisma/client';
import { Cache } from 'cache-manager';
import { ConfigService } from 'src/config/config.service';
import { PrismaService } from 'src/prisma/prisma.service';
@Injectable()
export class TenantService {
  constructor(
    private readonly configService: ConfigService,
    private readonly prismaService: PrismaService,
    @Inject(CACHE_MANAGER)
    private readonly cacheService: Cache,
  ) {}

  async cacheTenant(id: string, env: EEnviroment, tenant: UserTenant) {
    const KEY = `ha-cache-tenant:${env}:${id}`;
    const VALUE = JSON.stringify(tenant);
    await this.cacheService.set(KEY, VALUE);
  }

  async getCacheTenant(id: string, env: EEnviroment) {
    const KEY = `ha-cache-tenant:${env}:${id}`;
    const value: string = await this.cacheService.get(KEY);
    let tenant: UserTenant = null;
    if (value) {
      tenant = JSON.parse(value);
    }
    return tenant;
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
