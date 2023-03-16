import {
  All,
  Body,
  Controller,
  Head,
  Headers,
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

@Controller('reverse')
@UseGuards(JwtAuthGuard)
@ApiTags('Reverse Proxy')
export class ProxyController {
  constructor(
    private readonly httpService: HttpService,
    private readonly configService: ConfigService,
  ) {}

  @All('mainnet/*')
  reverseMainnet(
    @Request() req: IncomingMessage,
    @Query() query,
    @Body() body,
    @Headers() headers,
    @Param() param,
  ) {
    const url = param['*'];
    console.log(
      `[*]: Proxying ${req.method} request originally made to '${url}'...`,
    );
    return this.httpService.request({
      baseURL: this.configService.get('proxy.mainnetUrl'),
      method: req.method,
      url,
      data: body,
      params: query,
      headers: headers,
    });
  }

  @All('testnet/*')
  reverseTestnet(
    @Request() req: IncomingMessage,
    @Query() query,
    @Body() body,
    @Headers() headers,
    @Param() param,
  ) {
    const url = param['*'];
    console.log(
      `[*]: Proxying ${req.method} request originally made to '${url}'...`,
    );
    return this.httpService.request({
      baseURL: this.configService.get('proxy.testnetUrl'),
      method: req.method,
      url,
      data: body,
      params: query,
      headers: headers,
    });
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
