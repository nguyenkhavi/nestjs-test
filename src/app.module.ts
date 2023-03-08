import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { AppController } from './app.controller';
import { AppService } from './app.service';

import { appConfigs } from './config/config.service';
import { AppConfigModule } from './config/config.module';
import { PrismaModule } from './prisma/prisma.module';
import { AuthModule } from 'src/auth/auth.module';
import { MfaModule } from './mfa/mfa.module';

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
  ],

  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
