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
  throttleTTL: process.env.THROTTLE_TTL || 60,
  throttleLimit: process.env.THROTTLE_LIMIT || 30,
  hmacSecretKey: process.env.HMAC_SECRET_KEY,
}));

export const sendgridConfig = registerAs('sendgrid', () => ({
  key: process.env.SEND_GRID_KEY,
  confirmEmailTemplateId: process.env.CONFIRM_EMAIL_TEMPLATE_ID,
  forgotPasswordEmailTemplateId: process.env.FORGOT_PASSWORD_EMAIL_TEMPLATE_ID,
  resetPasswordEmailTemplateId: process.env.RESET_PASSWORD_EMAIL_TEMPLATE_ID,
  activeSecretShard: process.env.ACTIVE_SECRET_SHARD_EMAIL_TEMPLATE_ID,
  contactUsUrl: process.env.CONTACT_US_URL,
  termsOfUse: process.env.TERMS_OF_USE_URL,
  supportUrl: process.env.SUPPORT_URL,
}));
export const jwtConfig = registerAs('jwt', () => ({
  confirmSecret: process.env.JWT_CONFIRM_SECRET,
  confirmExpires: process.env.JWT_CONFIRM_EXPIRES,
  accessSecret: process.env.JWT_ACCESS_SECRET,
  accessExpires: process.env.JWT_ACCESS_EXPIRES,
  refreshSecret: process.env.JWT_REFRESH_SECRET,
  refreshExpires: process.env.JWT_REFRESH_EXPIRES,
}));

export const googleConfig = registerAs('google', () => ({
  clientId: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
}));

export const facebookConfig = registerAs('facebook', () => ({
  appId: process.env.FB_APP_ID,
  appSecret: process.env.FB_APP_SECRET,
}));

export const proxyConfig = registerAs('proxy', () => ({
  mainnetUrl: process.env.MAINNET_URL,
  testnetUrl: process.env.TESTNET_URL,
  testnetApiKey: process.env.TESTNET_API_KEY,
  mainnetApiKey: process.env.MAINNET_API_KEY,
}));

export const appConfigs = [
  appConfig,
  sendgridConfig,
  jwtConfig,
  googleConfig,
  facebookConfig,
  proxyConfig,
];

export class ConfigService extends NestjsConfigService<
  GetConfig<
    [
      typeof sendgridConfig,
      typeof appConfig,
      typeof jwtConfig,
      typeof googleConfig,
      typeof facebookConfig,
      typeof proxyConfig,
    ]
  >
> {}
