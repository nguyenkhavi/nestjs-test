import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { AppController } from './app.controller';
import { AppService } from './app.service';

import { appConfigs } from './config/config.service';
import { AppConfigModule } from './config/config.module';
import { PrismaModule } from './prisma/prisma.module';
import { AuthModule } from 'src/auth/auth.module';
import { MfaModule } from './mfa/mfa.module';
import { MailModule } from './mail/mail.module';
import { SsoModule } from './sso/sso.module';
import { UserProfileModule } from './user-profile/user-profile.module';
import { ProxyModule } from './proxy/proxy.module';
import { TenantModule } from './tenant/tenant.module';
import { ResetKeyRequestModule } from './reset-key-request/reset-key-request.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      load: appConfigs,
      envFilePath: ['.env'],
      // cache: true,
    }),
    AppConfigModule,
    AuthModule,
    PrismaModule,
    MfaModule,
    MailModule,
    SsoModule,
    UserProfileModule,
    ProxyModule,
    TenantModule,
    ResetKeyRequestModule,
  ],

  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
