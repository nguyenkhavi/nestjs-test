import {
  Injectable,
  NestInterceptor,
  CallHandler,
  BadRequestException,
  NotFoundException,
  UnauthorizedException,
  ForbiddenException,
} from '@nestjs/common';
import { Prisma } from '@prisma/client';
import { Observable, throwError } from 'rxjs';
import { catchError } from 'rxjs/operators';

const BUILTIN_EXCEPTIONS = [
  NotFoundException,
  BadRequestException,
  ForbiddenException,
  UnauthorizedException,
];

@Injectable()
export class ErrorsInterceptor implements NestInterceptor {
  intercept(_, next: CallHandler): Observable<any> {
    return next.handle().pipe(
      catchError((err: any) => {
        if (BUILTIN_EXCEPTIONS.some((ins) => err instanceof ins)) {
          throw err;
        }

        if (err instanceof Prisma.PrismaClientKnownRequestError) {
          return throwError(() => new NotFoundException(err.message));
        }
        return throwError(() => new BadRequestException(err.message));
      }),
    );
  }
}
