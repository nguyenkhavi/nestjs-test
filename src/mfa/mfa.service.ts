import {
  BadRequestException,
  CACHE_MANAGER,
  forwardRef,
  Inject,
  Injectable,
} from '@nestjs/common';
import * as speakeasy from 'speakeasy';
import { toDataURL } from 'qrcode';
import { Cache } from 'cache-manager';
import { _30MIN_MILLISECONDS_ } from 'src/utils/constants';
import { ConfigService } from '@nestjs/config';
import { AuthService } from 'src/auth/auth.service';
import { MFAVerifyDto } from 'src/mfa/mfa.dto';

@Injectable()
export class MfaService {
  constructor(
    @Inject(forwardRef(() => AuthService))
    private authService: AuthService,
    @Inject(CACHE_MANAGER)
    private readonly cacheService: Cache,
    private configService: ConfigService,
  ) {}
  mfaCodeValid(code: string, mfaSecret: string) {
    return speakeasy.totp.verify({
      secret: mfaSecret,
      encoding: 'base32',
      token: code,
    });
  }

  async generateMFASecret(uid: string) {
    const TEMP_MFA_SECRET_KEY = `temp-mfa-secret:${uid}`;
    const secret = speakeasy.generateSecret({
      name: this.configService.get('app.name'),
      length: 10, // ? Secret key length equal to 10, make the base 32 format of it have 16 char
      issuer: this.configService.get('app.name'),
    });

    await this.cacheService.set(
      TEMP_MFA_SECRET_KEY,
      secret.base32,
      _30MIN_MILLISECONDS_,
    );
    // await this.authService.enableMFA(uid, secret.base32);

    return secret;
  }

  async generateQrCodeDataURL(otpAuthUrl: string) {
    return toDataURL(otpAuthUrl);
  }

  async register(uid: string) {
    await this.authService.findOrThrow(uid);

    const { otpauth_url, base32 } = await this.generateMFASecret(uid);

    const qrCodeBase64 = await this.generateQrCodeDataURL(otpauth_url);
    return {
      data: {
        qrCodeBase64,
        secretBase32: base32,
      },
      meta: {
        uid,
      },
    };
  }

  async verify(uid: string, body: MFAVerifyDto) {
    await this.authService.findOrThrow(uid);

    const { mfaCode } = body;
    const TEMP_MFA_SECRET_KEY = `temp-mfa-secret:${uid}`;
    const currentSecret: string = await this.cacheService.get(
      TEMP_MFA_SECRET_KEY,
    );

    if (!currentSecret) {
      throw new BadRequestException('MFA Code is expired');
    }

    const mfaCodeMatching = this.mfaCodeValid(mfaCode, currentSecret);

    if (!mfaCodeMatching) {
      throw new BadRequestException('MFA Code is correct');
    }

    await this.authService.enableMFA(uid, currentSecret);
    await this.cacheService.del(TEMP_MFA_SECRET_KEY);
    return {
      data: { success: true, backUpKey: currentSecret },
      meta: { uid },
    };
  }

  async disable(uid: string) {
    const user = await this.authService.findOrThrow(uid);

    if (!user.mfaSecret) {
      throw new BadRequestException();
    }
    const updated = await this.authService.disableMFA(uid);
    return {
      data: {
        id: updated.id,
      },
    };
  }
}
