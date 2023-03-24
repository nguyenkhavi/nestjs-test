import { UnknownObject } from 'hmac-auth-express';
import { JWTPayload } from 'src/auth/auth.interface';

export interface ISecretShardPayload extends JWTPayload {
  domain: string;
  tenant: string;
  custonomyUserId: string;
}

export interface ICreateTenantBody extends UnknownObject {
  timezone: string;
  session: string;
}
