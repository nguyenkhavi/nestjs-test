import {
  All,
  Body,
  Controller,
  Head,
  InternalServerErrorException,
  Param,
  Query,
  Request,
  UseGuards,
} from '@nestjs/common';
import { ApiOperation, ApiTags } from '@nestjs/swagger';
import { IncomingMessage } from 'http';
import { HttpService } from '@nestjs/axios';
import { ConfigService } from 'src/config/config.service';
import { JwtAuthGuard } from 'src/auth/jwt/jwt-auth.guard';
import { firstValueFrom } from 'rxjs';
import { Authorization, Session } from 'src/utils/decorators';

@Controller('reverse')
@UseGuards(JwtAuthGuard)
@ApiTags('Reverse Proxy')
export class ProxyController {
  constructor(
    private readonly httpService: HttpService,
    private readonly configService: ConfigService,
  ) {}

  @All('mainnet/*')
  async reverseMainnet(
    @Request() req: IncomingMessage,
    @Query() query,
    @Body() body,
    @Authorization() authorization: string,
    @Session() session: string,
    @Param() param,
  ) {
    const url = param['*'];
    console.log(
      `[*][MAINNET]: Proxying ${req.method} request originally made to '${url}'...`,
    );
    try {
      const { data } = await firstValueFrom(
        this.httpService.request({
          baseURL: this.configService.get('proxy.mainnetUrl'),
          method: req.method,
          url,
          data: body,
          params: query,
          headers: {
            authorization,
            session,
          },
        }),
      );
      return { data };
    } catch (e) {
      console.log('[*][MAINNET]: Proxying Error', e);
      throw new InternalServerErrorException(e?.message);
    }
  }

  @All('testnet/*')
  async reverseTestnet(
    @Request() req: IncomingMessage,
    @Query() query,
    @Body() body,
    @Authorization() authorization: string,
    @Session() session: string,
    @Param() param,
  ) {
    const url = param['*'];
    console.log(
      `[*][TESTNET]: Proxying ${req.method} request originally made to '${url}'...`,
    );

    try {
      const { data } = await firstValueFrom(
        this.httpService.request({
          baseURL: this.configService.get('proxy.testnetUrl'),
          method: req.method,
          url,
          data: body,
          params: query,
          headers: {
            authorization,
            session,
          },
        }),
      );
      return { data };
    } catch (e) {
      console.log('[*][TESTNET]: Proxying Error', e);
      throw new InternalServerErrorException(e?.message);
    }
  }

  // Use this to show the UI Swagger
  @Head('mainnet')
  @ApiOperation({
    summary: `Reverse Request to Mainnet Env (${process.env.MAINNET_URL})`,
    description:
      'Example: http://127.0.0.1:8000/api/reverse/mainnet/v0/EL_s4eu/dau_du/projects/326f6e8b-9248-424c-9cce-dfec1b8b789b',
  })
  fakeMainnetFn() {
    return { data: true };
  }
  @Head('testnet')
  @ApiOperation({
    summary: `Reverse Request to Testnet Env (${process.env.TESTNET_URL})`,
    description:
      'Example: http://127.0.0.1:8000/api/reverse/testnet/v0/EL_s4eu/dau_du/projects/326f6e8b-9248-424c-9cce-dfec1b8b789b',
  })
  fakeTestnetFn() {
    return { data: true };
  }
}
