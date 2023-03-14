import { HttpService } from '@nestjs/axios';
import { Injectable } from '@nestjs/common';
import { UserTenant } from '@prisma/client';
import { firstValueFrom } from 'rxjs';
import { ConfigService } from 'src/config/config.service';
import { CreateTenantDto } from 'src/tenant/tenant.dto';

@Injectable()
export class TenantService {
  constructor(
    private readonly httpService: HttpService,
    private readonly configService: ConfigService,
  ) {}
  async createTestnetTenant(dto: CreateTenantDto) {
    const { token, timezone } = dto;
    const { data } = await firstValueFrom(
      this.httpService.request<Pick<UserTenant, 'signNodeId' | 'tenantId'>>({
        baseURL: this.configService.get('proxy.testnetUrl'),
        method: 'POST',
        url: 'v0/tenants',
        headers: {
          'api-key': this.configService.get('proxy.testnetApiKey'),
          Authorization: `Bearer ${token}`,
        },
        data: {
          timezone,
        },
      }),
    );
    return data;
  }
}
