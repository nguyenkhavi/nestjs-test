import { HttpService } from '@nestjs/axios';
import { Injectable } from '@nestjs/common';
import { EEnviroment, UserTenant } from '@prisma/client';
import { firstValueFrom } from 'rxjs';
import { ConfigService } from 'src/config/config.service';
import { CreateTenantDto } from 'src/tenant/tenant.dto';
import { generateHMACSignature } from 'src/utils/fn';

@Injectable()
export class CustonomyService {
  constructor(
    private readonly httpService: HttpService,
    private readonly configService: ConfigService,
  ) {}
  async checkUserExist(env: EEnviroment, accessToken: string) {
    const ENV_MAP = {
      [EEnviroment.TESTNET]: this.configService.get('proxy.testnetUrl'),
      [EEnviroment.MAINNET]: this.configService.get('proxy.mainnetUrl'),
    };
    const { data } = await firstValueFrom(
      this.httpService.request({
        baseURL: ENV_MAP[env],
        method: 'GET',
        url: 'v0/users',
        headers: {
          session: accessToken,
        },
      }),
    );
    return data;
  }

  async createTenant(env: EEnviroment, dto: CreateTenantDto) {
    const ENV_MAP = {
      [EEnviroment.TESTNET]: {
        BASE_URL: this.configService.get('proxy.testnetUrl'),
        API_KEY: this.configService.get('proxy.testnetApiKey'),
        HMAC_SECRET: this.configService.get('proxy.testnetHmacSecretKey'),
      },
      [EEnviroment.MAINNET]: {
        BASE_URL: this.configService.get('proxy.mainnetUrl'),
        API_KEY: this.configService.get('proxy.mainnetApiKey'),
        HMAC_SECRET: this.configService.get('proxy.mainnetHmacSecretKey'),
      },
    };
    const config = ENV_MAP[env];
    const { timezone, session } = dto;
    const body = {
      timezone,
      session,
    };
    const { data } = await firstValueFrom(
      this.httpService.request<
        Pick<UserTenant, 'signNodeId' | 'tenantId'> & { userId: string }
      >({
        baseURL: config.BASE_URL,
        method: 'POST',
        url: 'v0/tenants',
        headers: {
          'api-key': config.API_KEY,
          Authorization: generateHMACSignature(body, config.HMAC_SECRET),
        },
        data: body,
      }),
    );

    return data;
  }
  async updateRegisterMessage(
    tenant: string,
    domain: string,
    session: string,
    custonomyUserId: string,
    registerMsg: string,
  ) {
    const { data } = await firstValueFrom(
      this.httpService.request({
        baseURL: this.configService.get('proxy.mainnetUrl'),
        method: 'PATCH',
        url: `v0/${tenant}/${domain}/users`,
        headers: {
          session,
        },
        params: {
          action: 'registermanagednode',
        },
        data: {
          id: custonomyUserId,
          action: 'registermanagednode',
          authorizerId: custonomyUserId,
          registerMsg,
        },
      }),
    );

    return data;
  }

  async activeSecretShard(
    tenant: string,
    domain: string,
    session: string,
    custonomyUserId: string,
  ) {
    const { data } = await firstValueFrom(
      this.httpService.request({
        baseURL: this.configService.get('proxy.mainnetUrl'),
        method: 'PATCH',
        url: `v0/${tenant}/${domain}/users`,
        headers: {
          session,
        },
        params: {
          // action: "default",
        },
        data: {
          status: 'ACTIVE',
          id: custonomyUserId,
        },
      }),
    );

    return data;
  }
}
