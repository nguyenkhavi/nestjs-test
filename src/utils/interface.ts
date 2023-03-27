import UAParser from 'ua-parser-js';

export type IUserAgent = UAParser.IResult;

export type TSessionPrefix = 'CUSTOM' | 'FACEBOOK' | 'GOOGLE';
export type TSession = `${TSessionPrefix}:${string}`;
