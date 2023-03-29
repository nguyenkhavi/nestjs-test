import { HttpService } from '@nestjs/axios';
import { Injectable } from '@nestjs/common';
import { EEnviroment, UserTenant } from '@prisma/client';
import { generate } from 'hmac-auth-express';
import { firstValueFrom } from 'rxjs';
import { ConfigService } from 'src/config/config.service';
import { PrismaService } from 'src/prisma/prisma.service';
import { CreateTenantDto } from 'src/tenant/tenant.dto';
import { ICreateTenantBody } from 'src/tenant/tenant.interface';

@Injectable()
export class TenantService {
  constructor(
    private readonly httpService: HttpService,
    private readonly configService: ConfigService,
    private readonly prismaService: PrismaService,
  ) {}

  generateHMACSignature(
    body: ICreateTenantBody,
    secret: string,
    method = 'POST',
    path = 'v0/tenants',
  ) {
    const time = Date.now().toString();
    const digest = generate(secret, 'sha512', time, method, path, body).digest(
      'hex',
    );

    const hmac = `HMAC ${time}:${digest}`;
    return hmac;
  }

  async createTestnetTenant(dto: CreateTenantDto) {
    const { timezone, session } = dto;
    const body = {
      timezone,
      session,
    };
    const { data } = await firstValueFrom(
      this.httpService.request<
        Pick<UserTenant, 'signNodeId' | 'tenantId'> & { userId: string }
      >({
        baseURL: this.configService.get('proxy.testnetUrl'),
        method: 'POST',
        url: 'v0/tenants',
        headers: {
          'api-key': this.configService.get('proxy.testnetApiKey'),
          Authorization: this.generateHMACSignature(
            body,
            this.configService.getOrThrow('proxy.testnetHmacSecretKey'),
          ),
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
    console.log({ tenant, domain, session, custonomyUserId });

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
    console.log({ data });

    return data;
  }

  async createMainnetTenant(dto: CreateTenantDto) {
    const { timezone, session } = dto;
    const body = {
      timezone,
      session,
    };
    const { data } = await firstValueFrom(
      this.httpService.request<
        Pick<UserTenant, 'signNodeId' | 'tenantId'> & { userId: string }
      >({
        baseURL: this.configService.get('proxy.mainnetUrl'),
        method: 'POST',
        url: 'v0/tenants',
        headers: {
          'api-key': this.configService.get('proxy.mainnetApiKey'),
          Authorization: this.generateHMACSignature(
            body,
            this.configService.getOrThrow('proxy.mainnetHmacSecretKey'),
          ),
        },
        data: body,
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
