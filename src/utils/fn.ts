import { IUserAgent } from 'src/utils/interface';
import { ec } from 'elliptic';
import * as sha256 from 'sha256';
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
