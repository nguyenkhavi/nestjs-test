import {
  ConfigFactory,
  ConfigFactoryKeyHost,
  ConfigObject,
  registerAs,
  ConfigService as NestjsConfigService,
} from '@nestjs/config';

import { GetConfig } from './config';

declare module '@nestjs/config' {
  function registerAs<
    TConfig extends ConfigObject,
    TFactory extends ConfigFactory = ConfigFactory<TConfig>,
    Name extends string = '',
  >(
    token: Name,
    configFactory: TFactory,
  ): TFactory & ConfigFactoryKeyHost<ReturnType<TFactory>> & { name: Name };
}

export const appConfig = registerAs('app', () => ({
  nodeEnv: process.env.NODE_ENV,
  stage: process.env.STAGE,
  name: process.env.APP_NAME,
  port:
    parseInt((process.env.APP_PORT || process.env.PORT) as string, 10) || 8000,
  apiPrefix: process.env.API_PREFIX || 'api',
}));

export const sendgridConfig = registerAs('sendgrid', () => ({
  key: process.env.SEND_GRID_KEY,
}));

export const appConfigs = [appConfig, sendgridConfig];

export class ConfigService extends NestjsConfigService<
  GetConfig<[typeof sendgridConfig, typeof appConfig]>
> {}
