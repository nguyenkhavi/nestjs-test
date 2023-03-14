import { CacheModule, forwardRef, Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { JwtStrategy } from 'src/auth/jwt/jwt.strategy';
import { MailModule } from 'src/mail/mail.module';
import { MfaModule } from 'src/mfa/mfa.module';
import { PrismaModule } from 'src/prisma/prisma.module';
import { SsoModule } from 'src/sso/sso.module';
import { TenantModule } from 'src/tenant/tenant.module';
import { UserProfileModule } from 'src/user-profile/user-profile.module';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';

@Module({
  imports: [
    CacheModule.register(),
    PrismaModule,
    JwtModule,
    MailModule,
    SsoModule,
    forwardRef(() => UserProfileModule),
    forwardRef(() => MfaModule),
    TenantModule,
  ],

  controllers: [AuthController],
  providers: [AuthService, JwtStrategy],
  exports: [AuthService],
})
export class AuthModule {}
