import { JWTPayload } from 'src/auth/auth.interface';

export interface ISecretShardPayload extends JWTPayload {
  domain: string;
  tenant: string;
  custonomyUserId: string;
}
