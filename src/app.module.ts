import { Module, UseGuards } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { AppController } from './app.controller';
import { AppService } from './app.service';

import { appConfigs, ConfigService } from './config/config.service';
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
import { APP_GUARD } from '@nestjs/core';
import { ThrottlerGuard, ThrottlerModule } from '@nestjs/throttler';
import { CustonomyModule } from './custonomy/custonomy.module';
import { KmsModule } from './kms/kms.module';
@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      load: appConfigs,
      envFilePath: ['.env'],
      // cache: true,
    }),
    ThrottlerModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        ttl: config.get('app.throttleTTL'),
        limit: config.get('app.throttleLimit'),
      }),
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
    CustonomyModule,
    KmsModule,
  ],
  controllers: [AppController],
  providers: [
    AppService,
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard,
    },
  ],
})
@UseGuards(ThrottlerGuard)
export class AppModule {}
