import { IUserAgent } from 'src/utils/interface';
import { ec } from 'elliptic';
import * as sha256 from 'sha256';
import { ICreateTenantBody } from 'src/tenant/tenant.interface';
import { generate } from 'hmac-auth-express';
const EC = new ec('secp256k1');

export const formatBrowser = (userAgent: IUserAgent) => {
  return `${userAgent.browser.name} ${userAgent.browser.version}`;
};

export const generateKey = (pin: string) => {
  const pKey = sha256(pin);
  const key = EC.keyFromPrivate(pKey, 'hex');
  const secretShard = key.getPublic(true, 'hex');
  return secretShard;
};

export function generateHMACSignature(
  body: ICreateTenantBody,
  secret: string,
  method = 'POST',
  path = '/v0/tenants',
) {
  const time = Date.now().toString();
  const digest = generate(secret, 'sha512', time, method, path, body).digest(
    'hex',
  );

  const hmac = `HMAC ${time}:${digest}`;
  return hmac;
}
