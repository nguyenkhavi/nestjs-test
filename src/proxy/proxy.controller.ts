import {
  All,
  Body,
  Controller,
  Get,
  Head,
  InternalServerErrorException,
  Param,
  Query,
  Request,
  Res,
  UseGuards,
} from '@nestjs/common';
import { ApiOperation, ApiTags } from '@nestjs/swagger';
import { IncomingMessage } from 'http';
import { HttpService } from '@nestjs/axios';
import { ConfigService } from 'src/config/config.service';
import { JwtAuthGuard } from 'src/auth/jwt/jwt-auth.guard';
import { firstValueFrom } from 'rxjs';
import { Authorization, Session } from 'src/utils/decorators';
import { TSession } from 'src/utils/interface';
import { GetPreviewDto } from 'src/proxy/proxy.dto';
import { Response } from 'express';

@Controller('reverse')
@ApiTags('Reverse Proxy')
export class ProxyController {
  constructor(
    private readonly httpService: HttpService,
    private readonly configService: ConfigService,
  ) {}

  @Get('mainnet/branding-preview')
  @ApiOperation({
    summary: `Get Mainnet Branding Preview`,
  })
  async reverseMainnetBrandingPreview(
    @Query() query: GetPreviewDto,
    @Res() res: Response,
  ) {
    const { data } = await firstValueFrom(
      this.httpService.request({
        baseURL: this.configService.get('proxy.mainnetUrl'),
        method: 'GET',
        url: 'v0/community/branding_preview',

        params: query,
      }),
    );
    res.type('html').send(data);
    return {};
  }
  @Get('testnet/branding-preview')
  @ApiOperation({
    summary: `Get Testnet Branding`,
  })
  async reverseTestnetBrandingPreview(
    @Query() query: GetPreviewDto,
    @Res() res: Response,
  ) {
    const { data } = await firstValueFrom(
      this.httpService.request({
        baseURL: this.configService.get('proxy.testnetUrl'),
        method: 'GET',
        url: 'v0/community/branding_preview',
        params: query,
      }),
    );
    res.type('html').send(data);
    return {};
  }

  @All('mainnet/*')
  @UseGuards(JwtAuthGuard)
  async reverseMainnet(
    @Request() req: IncomingMessage,
    @Query() query,
    @Body() body,
    @Authorization() authorization: string,
    @Session() session: TSession,
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
  @UseGuards(JwtAuthGuard)
  async reverseTestnet(
    @Request() req: IncomingMessage,
    @Query() query,
    @Body() body,
    @Authorization() authorization: string,
    @Session() session: TSession,
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
  @UseGuards(JwtAuthGuard)
  fakeMainnetFn() {
    return { data: true };
  }
  @Head('testnet')
  @ApiOperation({
    summary: `Reverse Request to Testnet Env (${process.env.TESTNET_URL})`,
    description:
      'Example: http://127.0.0.1:8000/api/reverse/testnet/v0/EL_s4eu/dau_du/projects/326f6e8b-9248-424c-9cce-dfec1b8b789b',
  })
  @UseGuards(JwtAuthGuard)
  fakeTestnetFn() {
    return { data: true };
  }
}
