import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { JWTPayload } from 'src/auth/auth.interface';
import { IUserAgent } from 'src/utils/interface';
import { UAParser } from 'ua-parser-js';

export const UserAgent = createParamDecorator(
  (_: string, ctx: ExecutionContext) => {
    const request = ctx
      .switchToHttp()
      .getRequest<Request & { user?: JWTPayload }>();
    const userAgentString = request.headers['user-agent'];
    const parser = new UAParser(userAgentString); // you need to pass the user-agent for nodejs
    const userAgent = parser.getResult();
    return userAgent as IUserAgent;
  },
);

export const Origin = createParamDecorator(
  (_: string, ctx: ExecutionContext) => {
    const request = ctx
      .switchToHttp()
      .getRequest<Request & { user?: JWTPayload }>();

    return request.headers['origin'];
  },
);

export const Uid = createParamDecorator((_: string, ctx: ExecutionContext) => {
  const request = ctx
    .switchToHttp()
    .getRequest<Request & { user?: JWTPayload }>();

  return request.user.uid;
});

export const Authorization = createParamDecorator(
  (_: string, ctx: ExecutionContext) => {
    const request = ctx
      .switchToHttp()
      .getRequest<Request & { user?: JWTPayload }>();

    return request.headers['authorization'] || request.headers['Authorization'];
  },
);

export const Session = createParamDecorator(
  (_: string, ctx: ExecutionContext) => {
    const request = ctx
      .switchToHttp()
      .getRequest<Request & { user?: JWTPayload }>();

    return request.headers['session'];
  },
);
