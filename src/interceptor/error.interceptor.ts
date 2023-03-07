import {
  Injectable,
  NestInterceptor,
  CallHandler,
  BadRequestException,
  NotFoundException,
} from '@nestjs/common';
import { Observable, throwError } from 'rxjs';
import { catchError } from 'rxjs/operators';

const BUILTIN_EXCEPTIONS = [NotFoundException, BadRequestException];

@Injectable()
export class ErrorsInterceptor implements NestInterceptor {
  intercept(_, next: CallHandler): Observable<any> {
    return next.handle().pipe(
      catchError((err: any) => {
        if (BUILTIN_EXCEPTIONS.some((ins) => err instanceof ins)) {
          throw err;
        }
        return throwError(() => new BadRequestException(err.message));
      }),
    );
  }
}
