import * as bcrypt from 'bcrypt';

import {
  BadRequestException,
  CACHE_MANAGER,
  ConflictException,
  HttpException,
  HttpStatus,
  Inject,
  Injectable,
} from '@nestjs/common';
import {
  ConfirmEmailDto,
  ResendConfirmEmailDto,
  UserRegisterDto,
} from 'src/auth/auth.dto';
import { PrismaService } from 'src/prisma/prisma.service';
import { JwtService } from '@nestjs/jwt';
import { JWTPayload } from 'src/auth/auth.interface';
import { ConfigService } from 'src/config/config.service';
import { Cache } from 'cache-manager';
import {
  _24H_MILLISECONDS_,
  _30MIN_MILLISECONDS_,
  _30_MILLISECOND_,
} from 'src/utils/constants';

@Injectable()
export class AuthService {
  constructor(
    private readonly prismaService: PrismaService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
    @Inject(CACHE_MANAGER)
    private readonly cacheService: Cache,
  ) {}

  async sendConfirmEmail(uid: string, email: string) {
    const CACHE_KEY = `confirm-sent:${uid}`;
    const RECENTLY_SENT_KEY = `recently-sent:${uid}`;
    const LATEST_TOKEN_KEY = `latest-token:${uid}`;

    const sentCount: number = await this.cacheService.get(CACHE_KEY);
    const recentlySent = await this.cacheService.get(RECENTLY_SENT_KEY);
    if (+sentCount >= 5 || recentlySent) {
      throw new HttpException(
        {
          statusCode: HttpStatus.TOO_MANY_REQUESTS,
          error: 'Too Many Requests',
          message: 'Rate limit exceeded.',
        },
        429,
      );
    } else {
      const payload: JWTPayload = {
        uid,
      };
      const token = this.jwtService.sign(payload, {
        secret: this.configService.get('jwt.confirmSecret'),
        expiresIn: this.configService.get('jwt.confirmExpires'),
      });

      // TODO: handle send mail

      await this.cacheService.set(
        CACHE_KEY,
        (sentCount || 0) + 1,
        _24H_MILLISECONDS_,
      );
      await this.cacheService.set(RECENTLY_SENT_KEY, token, _30_MILLISECOND_);
      await this.cacheService.set(
        LATEST_TOKEN_KEY,
        token,
        _30MIN_MILLISECONDS_,
      );
      console.log({ token, sentCount, recentlySent });
    }
    return sentCount;
  }

  async register(body: UserRegisterDto) {
    // const user = this.prismaService.user.create();
    const { email, password } = body;
    await this.prismaService.user.deleteMany();
    const existUserWithEmail = await this.prismaService.user.findUnique({
      where: { email },
    });
    if (existUserWithEmail) {
      throw new ConflictException('Email is not available!');
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const { id } = await this.prismaService.user.create({
      data: {
        email,
        password: hashedPassword,
      },
      select: {
        id: true,
      },
    });
    this.sendConfirmEmail(id, email);
    return { data: { id }, meta: { id } };
  }

  async resendConfirmEmail(body: ResendConfirmEmailDto) {
    const { id } = body;
    const user = await this.prismaService.user.findUniqueOrThrow({
      where: { id },
      select: { email: true, emailVerified: true },
    });
    if (user.emailVerified) {
      throw new BadRequestException('Email is already confirmed');
    }
    await this.sendConfirmEmail(id, user.email);

    return { data: { id }, meta: { id } };
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

    await this.prismaService.user.update({
      where: {
        id: uid,
      },
      data: {
        emailVerified: true,
      },
    });

    return {};
  }
}
