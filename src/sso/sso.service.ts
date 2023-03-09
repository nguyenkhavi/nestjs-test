import { Injectable } from '@nestjs/common';
import { OAuth2Client } from 'google-auth-library';
import { Facebook } from 'fb';
import { ConfigService } from 'src/config/config.service';
import { ISocialProfile } from 'src/sso/sso.interface';
import { SSODto } from 'src/auth/auth.dto';

@Injectable()
export class SsoService {
  private google: OAuth2Client;
  private fb;

  constructor(private configService: ConfigService) {
    this.google = new OAuth2Client(
      configService.get('google.clientId'),
      configService.get('google.clientSecret'),
    );
    this.fb = new Facebook({
      appId: configService.get('facebook.appId'),
      appSecret: configService.get('facebook.appSecret'),
      version: 'v7.0',
    });
  }

  async getGoogleProfile(body: SSODto) {
    const { idToken } = body;
    const ticket = await this.google.verifyIdToken({
      idToken,
      audience: [this.configService.get('google.clientId')],
    });

    const data = ticket.getPayload();

    return {
      id: data.sub,
      email: data.email,
      firstName: data.given_name,
      lastName: data.family_name,
    };
  }

  async getFacebookProfile(body: SSODto) {
    const { idToken } = body;

    this.fb.setAccessToken(idToken);
    const data: ISocialProfile = await new Promise((resolve) => {
      this.fb.api(
        '/me',
        'get',
        { fields: 'id,last_name,email,first_name' },
        (response) => {
          resolve(response);
        },
      );
    });
    return {
      id: data.id,
      email: data.email,
      firstName: data.first_name,
      lastName: data.last_name,
    };
  }
}
