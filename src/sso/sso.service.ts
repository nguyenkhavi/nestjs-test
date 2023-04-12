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
      'postmessage',
    );
    this.fb = new Facebook({
      appId: configService.get('facebook.appId'),
      appSecret: configService.get('facebook.appSecret'),
      version: 'v7.0',
    });
  }

  // async getGoogleProfile(body: SSODto) {
  //   const { token } = body;
  //   const ticket = await this.google.verifyIdToken({
  //     idToken: token,
  //     audience: [this.configService.get('google.clientId')],
  //   });

  //   const data = ticket.getPayload();

  //   return {
  //     id: data.sub,
  //     email: data.email,
  //     name: data.name,
  //     avatar: data.picture,
  //   };
  // }

  async getGoogleProfileByCode(code: string) {
    const { tokens } = await this.google.getToken(code);

    const ticket = await this.google.verifyIdToken({
      idToken: tokens.id_token,
      audience: [this.configService.get('google.clientId')],
    });

    const data = ticket.getPayload();

    return {
      id: data.sub,
      email: data.email,
      name: data.name,
      avatar: data.picture,
      token: tokens.id_token,
    };
  }

  async getFacebookProfile(body: SSODto) {
    const { token } = body;

    this.fb.setAccessToken(token);
    const data: ISocialProfile = await this.fb.api('/me', 'get', {
      fields: 'id,name,email',
    });

    return {
      id: data.id,
      email: data.email,
      name: data.name,
      avatar: `https://graph.facebook.com/${data.id}/picture?type=normal`,
    };
  }
}
