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
  confirmEmailTemplateId: process.env.CONFIRM_EMAIL_TEMPLATE_ID,
  forgotPasswordEmailTemplateId: process.env.FORGOT_PASSWORD_EMAIL_TEMPLATE_ID,
  resetPasswordEmailTemplateId: process.env.RESET_PASSWORD_EMAIL_TEMPLATE_ID,
  contactUsUrl: process.env.CONTACT_US_URL,
  termsOfUse: process.env.TERMS_OF_USE_URL,
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

export const appConfigs = [
  appConfig,
  sendgridConfig,
  jwtConfig,
  googleConfig,
  facebookConfig,
];

export class ConfigService extends NestjsConfigService<
  GetConfig<
    [
      typeof sendgridConfig,
      typeof appConfig,
      typeof jwtConfig,
      typeof googleConfig,
      typeof facebookConfig,
    ]
  >
> {}
