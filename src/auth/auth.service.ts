import * as bcrypt from 'bcrypt';

import {
  BadRequestException,
  CACHE_MANAGER,
  ConflictException,
  forwardRef,
  HttpException,
  HttpStatus,
  Inject,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import {
  ChangePasswordDto,
  ConfirmEmailDto,
  ForgotPasswordDto,
  LoginDto,
  PutPasswordDto,
  RefreshTokenDto,
  ResendConfirmEmailDto,
  SSODto,
  UserRegisterDto,
  VerifyPasswordDto,
} from 'src/auth/auth.dto';
import { PrismaService } from 'src/prisma/prisma.service';
import { JwtService } from '@nestjs/jwt';
import { IRequestClient, JWTPayload } from 'src/auth/auth.interface';
import { ConfigService } from 'src/config/config.service';
import { Cache } from 'cache-manager';
import {
  // MAX_CONFIRM_SENT_PER_DAY,
  // MAX_FORGOT_PASS_SENT_PER_DAY,
  // _24H_MILLISECONDS_,
  _30MIN_MILLISECONDS_,
  _30S_MILLISECOND_,
} from 'src/utils/constants';
import { EUserStatus, User } from '@prisma/client';
import { MfaService } from 'src/mfa/mfa.service';
import { MailService } from 'src/mail/mail.service';
import { formatBrowser } from 'src/utils/fn';
import { SsoService } from 'src/sso/sso.service';
import { UserProfileService } from 'src/user-profile/user-profile.service';
import { TenantService } from 'src/tenant/tenant.service';

@Injectable()
export class AuthService {
  constructor(
    private readonly prismaService: PrismaService,
    private readonly mailService: MailService,
    private readonly tenantService: TenantService,
    private readonly ssoService: SsoService,
    private readonly jwtService: JwtService,
    @Inject(forwardRef(() => MfaService))
    private readonly mfaService: MfaService,
    @Inject(forwardRef(() => UserProfileService))
    private readonly userProfileService: UserProfileService,

    private readonly configService: ConfigService,
    @Inject(CACHE_MANAGER)
    private readonly cacheService: Cache,
  ) {}

  async verifyToken(id: string) {
    const user = await this.findOrThrow(id);
    return { data: { id, email: user.email } };
  }

  async findOrThrow(id: string) {
    return this.prismaService.user.findFirstOrThrow({
      where: {
        id,
        emailVerified: true,
        status: EUserStatus.ACTIVE,
      },
    });
  }

  private generateConfirmUrl(origin: string, token: string) {
    return `${origin}/mail-handler/verify-email?token=${token}`;
  }

  private generateForgotPasswordUrl(origin: string, token: string) {
    return `${origin}/mail-handler/forgot-password?token=${token}`;
  }

  // private generateResetPasswordUrl(origin: string, token: string) {
  //   return `${origin}/reset-password?token=${token}`;
  // }

  async sendConfirmEmail(
    uid: string,
    email: string,
    requestClient: IRequestClient,
  ) {
    // const CACHE_KEY = `confirm-sent:${uid}`;
    const RECENTLY_SENT_KEY = `recently-sent:${uid}`;
    const LATEST_TOKEN_KEY = `latest-token:${uid}`;

    // const sentCount: number = await this.cacheService.get(CACHE_KEY);
    const recentlySent = await this.cacheService.get(RECENTLY_SENT_KEY);
    if (recentlySent) {
      throw new HttpException(
        {
          statusCode: HttpStatus.TOO_MANY_REQUESTS,
          error: 'Too Many Requests',
          message: 'Rate limit exceeded.',
        },
        HttpStatus.TOO_MANY_REQUESTS,
      );
    } else {
      const payload: JWTPayload = {
        uid,
      };
      const token = this.jwtService.sign(payload, {
        secret: this.configService.get('jwt.confirmSecret'),
        expiresIn: this.configService.get('jwt.confirmExpires'),
      });

      await this.mailService.send({
        to: email,
        from: 'huy.pham@spiritlabs.co',
        templateId: 'sendgrid.confirmEmailTemplateId',
        dynamicTemplateData: {
          urlVerifyEmail: this.generateConfirmUrl(requestClient.origin, token),
          browser: formatBrowser(requestClient.userAgent),
          ipAddress: requestClient.ip,
          emailWasSentTo: email,
          urlContactUs: this.configService.get('sendgrid.contactUsUrl'),
          urlTermsOfUse: this.configService.get('sendgrid.termsOfUse'),
        },
      });

      // await this.cacheService.set(
      //   CACHE_KEY,
      //   (sentCount || 0) + 1,
      //   _24H_MILLISECONDS_,
      // );
      await this.cacheService.set(RECENTLY_SENT_KEY, token, _30S_MILLISECOND_);
      await this.cacheService.set(
        LATEST_TOKEN_KEY,
        token,
        _30MIN_MILLISECONDS_,
      );
      console.log(`sendConfirmEmail for ${email}: ${token}`);
    }
    return true;
  }

  async register(body: UserRegisterDto, requestClient: IRequestClient) {
    const { email, password, timezone } = body;
    const existUserWithEmail = await this.prismaService.user.findFirst({
      where: {
        email,
        googleUid: null,
        facebookUid: null,
      },
    });
    if (existUserWithEmail && existUserWithEmail.emailVerified) {
      throw new ConflictException('Email is not available!');
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    let id = existUserWithEmail?.id;
    if (!id) {
      const createdUser = await this.prismaService.user.create({
        data: {
          email,
          password: hashedPassword,
          timezone,
        },
        select: {
          id: true,
        },
      });
      id = createdUser.id;
      await this.userProfileService.createDefaultProfile(id);
    }

    this.sendConfirmEmail(id, email, requestClient);
    return { data: { id } };
  }

  async resendConfirmEmail(
    body: ResendConfirmEmailDto,
    requestClient: IRequestClient,
  ) {
    const { email } = body;
    const user = await this.prismaService.user.findFirstOrThrow({
      where: { email, googleUid: null, facebookUid: null },
      select: { email: true, emailVerified: true, id: true },
    });
    if (user.emailVerified) {
      throw new BadRequestException('Email is already confirmed');
    }
    const success = await this.sendConfirmEmail(
      user.id,
      user.email,
      requestClient,
    );
    return { data: { id: user.id, success } };
  }

  async confirmEmail(body: ConfirmEmailDto) {
    const { token } = body;

    const payload: JWTPayload = this.jwtService.verify(token, {
      secret: this.configService.get('jwt.confirmSecret'),
    });
    const { uid } = payload;
    const LATEST_TOKEN_KEY = `latest-token:${uid}`;

    const latestToken = await this.cacheService.get(LATEST_TOKEN_KEY);
    if (latestToken !== token) {
      throw new BadRequestException('Token is expired');
    }

    const user = await this.prismaService.user.update({
      where: {
        id: uid,
      },
      data: {
        emailVerified: true,
      },
    });

    const data = await this.generateAuthorizedResponse(user);

    const testTenant = await this.tenantService.createTestnetTenant({
      timezone: user.timezone,
      token: data.accessToken,
    });

    await this.prismaService.userTenant.create({
      data: {
        userId: user.id,
        signNodeId: testTenant.signNodeId,
        tenantId: testTenant.tenantId,
      },
    });

    return { data };
  }

  async sendForgotPasswordEmail(
    uid: string,
    email: string,
    requestClient: IRequestClient,
  ) {
    // const CACHE_KEY = `forgot-sent:${uid}`;
    const RECENTLY_SENT_KEY = `recently-forgot-sent:${uid}`;
    const LATEST_TOKEN_KEY = `latest-forgot-token:${uid}`;

    // const sentCount: number = await this.cacheService.get(CACHE_KEY);
    const recentlySent = await this.cacheService.get(RECENTLY_SENT_KEY);
    if (recentlySent) {
      throw new HttpException(
        {
          statusCode: HttpStatus.TOO_MANY_REQUESTS,
          error: 'Too Many Requests',
          message: 'Rate limit exceeded.',
        },
        HttpStatus.TOO_MANY_REQUESTS,
      );
    } else {
      const payload: JWTPayload = {
        uid,
      };
      const token = this.jwtService.sign(payload, {
        secret: this.configService.get('jwt.confirmSecret'),
        expiresIn: this.configService.get('jwt.confirmExpires'),
      });

      await this.mailService.send({
        to: email,
        from: 'huy.pham@spiritlabs.co',
        templateId: 'sendgrid.forgotPasswordEmailTemplateId',
        dynamicTemplateData: {
          urlResetPassword: this.generateForgotPasswordUrl(
            requestClient.origin,
            token,
          ),
          browser: formatBrowser(requestClient.userAgent),
          ipAddress: requestClient.ip,
          emailWasSentTo: email,
          urlContactUs: this.configService.get('sendgrid.contactUsUrl'),
          urlTermsOfUse: this.configService.get('sendgrid.termsOfUse'),
        },
      });

      // await this.cacheService.set(
      //   CACHE_KEY,
      //   (sentCount || 0) + 1,
      //   _24H_MILLISECONDS_,
      // );
      await this.cacheService.set(RECENTLY_SENT_KEY, token, _30S_MILLISECOND_);
      await this.cacheService.set(
        LATEST_TOKEN_KEY,
        token,
        _30MIN_MILLISECONDS_,
      );
    }
    return true;
  }
  async forgotPassword(body: ForgotPasswordDto, requestClient: IRequestClient) {
    const { email } = body;
    const user = await this.prismaService.user.findFirstOrThrow({
      where: {
        email,
        googleUid: null,
        facebookUid: null,
      },
    });
    const success = await this.sendForgotPasswordEmail(
      user.id,
      user.email,
      requestClient,
    );
    return { data: { success } };
  }

  async putPassword(body: PutPasswordDto) {
    const { token, password } = body;

    const payload: JWTPayload = this.jwtService.verify(token, {
      secret: this.configService.get('jwt.confirmSecret'),
    });
    const { uid } = payload;
    const user = await this.prismaService.user.findUniqueOrThrow({
      where: {
        id: uid,
      },
    });

    const LATEST_TOKEN_KEY = `latest-forgot-token:${uid}`;

    const latestToken = await this.cacheService.get(LATEST_TOKEN_KEY);
    if (latestToken !== token) {
      throw new BadRequestException('Token is expired');
    }

    await this.prismaService.passwordHistory.create({
      data: {
        userId: user.id,
        password: user.password,
      },
    });

    const hashedPassword = await bcrypt.hash(password, 10);

    await this.prismaService.user.update({
      where: {
        id: uid,
      },
      data: {
        password: hashedPassword,
      },
    });

    this.mailService.send({
      to: user.email,
      from: 'huy.pham@spiritlabs.co',
      templateId: 'sendgrid.resetPasswordEmailTemplateId',
      dynamicTemplateData: {
        urlSupport: this.configService.get('sendgrid.supportUrl'),
        emailWasSentTo: user.email,
        urlContactUs: this.configService.get('sendgrid.contactUsUrl'),
        urlTermsOfUse: this.configService.get('sendgrid.termsOfUse'),
      },
    });

    return {};
  }

  private async generateAuthorizedResponse(user: User) {
    const jwtPayload: JWTPayload = {
      uid: user.id,
    };
    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(jwtPayload, {
        secret: this.configService.get('jwt.accessSecret'),
        expiresIn: this.configService.get('jwt.accessExpires'),
      }),
      this.jwtService.signAsync(jwtPayload, {
        secret: this.configService.get('jwt.refreshSecret'),
        expiresIn: this.configService.get('jwt.refreshExpires'),
      }),
    ]);
    await this.prismaService.userToken.create({
      data: {
        userId: user.id,
        refreshToken,
      },
    });
    const userWithTenant = await this.prismaService.user.findUnique({
      where: {
        id: user.id,
      },
      include: {
        tenants: true,
      },
    });
    const {
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      password: _,
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      mfaSecret: __,
      ...userWithoutSensitive
    } = userWithTenant;
    return {
      accessToken,
      refreshToken,
      data: userWithoutSensitive,
    };
  }

  async login(body: LoginDto) {
    const { email, password, mfaCode } = body;
    const user = await this.prismaService.user.findFirstOrThrow({
      where: {
        email,
        emailVerified: true,
      },
      include: {
        tenants: true,
      },
    });
    const passwordMatching = await bcrypt.compare(password, user.password);
    if (!passwordMatching || !user) {
      throw new UnauthorizedException('Incorrect credential!');
    }

    const mfaRequired = !!user.mfaSecret;
    if (mfaRequired) {
      if (!mfaCode) {
        return {
          data: {
            mfaRequired: true,
          },
        };
      } else {
        const mfaValid = this.mfaService.mfaCodeValid(mfaCode, user.mfaSecret);

        if (!mfaValid) {
          throw new UnauthorizedException('Incorrect credential!');
        }
      }
    }

    const data = await this.generateAuthorizedResponse(user);
    return { data };
  }

  async refreshToken(body: RefreshTokenDto) {
    const { refreshToken } = body;

    const userToken = await this.prismaService.userToken.findFirstOrThrow({
      where: {
        refreshToken,
      },
    });

    const payload: JWTPayload = this.jwtService.verify(refreshToken, {
      secret: this.configService.get('jwt.refreshSecret'),
    });
    if (!userToken || payload.uid !== userToken.userId) {
      throw new UnauthorizedException();
    }

    const user = await this.prismaService.user.findUniqueOrThrow({
      where: {
        id: payload.uid,
      },
    });

    const data = await this.generateAuthorizedResponse(user);
    this.prismaService.userToken.delete({
      where: {
        id: userToken.id,
      },
    });
    return { data };
  }

  async ssoGoogle(body: SSODto) {
    const { mfaCode, timezone } = body;
    const profile = await this.ssoService.getGoogleProfile(body);

    if (!profile) {
      throw new BadRequestException('Cannot verify account from SSO Provider');
    }

    const { id: googleUid, email } = profile;

    let user = await this.prismaService.user.findFirst({
      where: {
        googleUid,
      },
    });

    if (user) {
      const mfaRequired = !!user.mfaSecret;
      if (mfaRequired) {
        if (!mfaCode) {
          return {
            data: {
              mfaRequired: true,
            },
          };
        } else {
          const mfaValid = this.mfaService.mfaCodeValid(
            mfaCode,
            user.mfaSecret,
          );

          if (!mfaValid) {
            throw new UnauthorizedException('Incorrect credential!');
          }
        }
      }
    } else {
      const hashedPassword = await bcrypt.hash(
        Math.ceil(Math.random() * 1000000).toString(),
        10,
      );

      user = await this.prismaService.user.create({
        data: {
          email,
          password: hashedPassword,
          emailVerified: true,
          googleUid,
          timezone,
        },
      });
      await this.userProfileService.createDefaultProfile(
        user.id,
        profile.name,
        profile.avatar,
      );
    }

    const data = await this.generateAuthorizedResponse(user);

    if (!data.data.tenants?.length) {
      const testTenant = await this.tenantService.createTestnetTenant({
        timezone: user.timezone,
        token: data.accessToken,
      });

      const tenant = await this.prismaService.userTenant.create({
        data: {
          userId: user.id,
          signNodeId: testTenant.signNodeId,
          tenantId: testTenant.tenantId,
        },
      });

      data.data.tenants = [tenant];
    }

    return { data };
  }

  async ssoFacebook(body: SSODto) {
    const { mfaCode, timezone } = body;
    const profile = await this.ssoService.getFacebookProfile(body);

    if (!profile) {
      throw new BadRequestException('Cannot verify account from SSO Provider');
    }

    const { id: facebookUid, email } = profile;

    let user = await this.prismaService.user.findFirst({
      where: {
        facebookUid,
      },
    });

    if (user) {
      const mfaRequired = !!user.mfaSecret;
      if (mfaRequired) {
        if (!mfaCode) {
          return {
            data: {
              mfaRequired: true,
            },
          };
        } else {
          const mfaValid = this.mfaService.mfaCodeValid(
            mfaCode,
            user.mfaSecret,
          );

          if (!mfaValid) {
            throw new UnauthorizedException('Incorrect credential!');
          }
        }
      }
    } else {
      const hashedPassword = await bcrypt.hash(
        Math.ceil(Math.random() * 1000000).toString(),
        10,
      );

      user = await this.prismaService.user.create({
        data: {
          email,
          password: hashedPassword,
          emailVerified: true,
          facebookUid,
          timezone,
        },
      });
      await this.userProfileService.createDefaultProfile(
        user.id,
        profile.name,
        profile.avatar,
      );
    }

    const data = await this.generateAuthorizedResponse(user);

    if (!data.data.tenants?.length) {
      const testTenant = await this.tenantService.createTestnetTenant({
        timezone: user.timezone,
        token: data.accessToken,
      });

      const tenant = await this.prismaService.userTenant.create({
        data: {
          userId: user.id,
          signNodeId: testTenant.signNodeId,
          tenantId: testTenant.tenantId,
        },
      });

      data.data.tenants = [tenant];
    }

    return { data };
  }

  async mfaRequired(userId: string) {
    const user = await this.prismaService.user.findUniqueOrThrow({
      where: {
        id: userId,
      },
    });

    return !!user.mfaSecret;
  }

  enableMFA(userId: string, mfaSecret: string) {
    return this.prismaService.user.update({
      where: {
        id: userId,
      },
      data: {
        mfaSecret,
      },
    });
  }

  disableMFA(userId: string) {
    return this.prismaService.user.update({
      where: {
        id: userId,
      },
      data: {
        mfaSecret: null,
      },
    });
  }

  async verifyPassword(uid: string, body: VerifyPasswordDto) {
    const { mfaCode, password } = body;
    const user = await this.prismaService.user.findFirstOrThrow({
      where: {
        id: uid,
        googleUid: null,
        facebookUid: null,
      },
    });

    const passwordMatching = await bcrypt.compare(password, user.password);
    if (!passwordMatching || !user) {
      throw new UnauthorizedException('Incorrect credential!');
    }

    const mfaRequired = !!user.mfaSecret;
    if (mfaRequired) {
      if (!mfaCode) {
        return {
          data: {
            mfaRequired: true,
          },
        };
      } else {
        const mfaValid = this.mfaService.mfaCodeValid(mfaCode, user.mfaSecret);

        if (!mfaValid) {
          throw new UnauthorizedException('Incorrect credential!');
        }
      }
    }

    return { data: { success: true } };
  }

  async changePassword(uid: string, body: ChangePasswordDto) {
    const { password, mfaCode, newPassword } = body;
    const { data: verifiedData } = await this.verifyPassword(uid, {
      password,
      mfaCode,
    });

    if (verifiedData.mfaRequired) {
      return {
        data: verifiedData,
      };
    }

    if (verifiedData.success) {
      const user = await this.prismaService.user.findFirstOrThrow({
        where: {
          id: uid,
          googleUid: null,
          facebookUid: null,
        },
      });
      await this.prismaService.passwordHistory.create({
        data: {
          userId: user.id,
          password: user.password,
        },
      });
      const hashedPassword = await bcrypt.hash(newPassword, 10);
      await this.prismaService.user.update({
        where: {
          id: uid,
        },
        data: {
          password: hashedPassword,
        },
      });
    }
    return { data: { success: true } };
  }

  async getUserWithoutSensitive(id: string) {
    const user = await this.prismaService.user.findUniqueOrThrow({
      where: {
        id,
      },
      include: {
        tenants: true,
        profile: true,
      },
    });

    const mfaRequired = !!user.mfaSecret;
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { password: _, mfaSecret: __, ...userWithoutSensitive } = user;
    return {
      ...userWithoutSensitive,
      mfaRequired,
    };
  }

  async getLastChangedPassword(uid: string) {
    const historyRecord = await this.prismaService.passwordHistory.findFirst({
      where: {
        userId: uid,
      },
      select: {
        createdAt: true,
      },
      orderBy: {
        createdAt: 'desc',
      },
      take: 1,
    });
    return historyRecord || null;
  }
}
