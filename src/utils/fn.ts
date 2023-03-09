import { IUserAgent } from 'src/utils/interface';

export const formatBrowser = (userAgent: IUserAgent) => {
  return `${userAgent.browser.name} ${userAgent.browser.version}`;
};
