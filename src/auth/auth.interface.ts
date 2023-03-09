import { IUserAgent } from 'src/utils/interface';

export interface JWTPayload {
  uid: string;
}

export interface IRequestClient {
  ip: string;
  userAgent: IUserAgent;
  origin: string;
}
