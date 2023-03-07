import { Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';

@Injectable()
export class AuthService {
  constructor(private readonly prismaService: PrismaService) {}
  register() {
    const user = this.prismaService.user.create();
    return 'Hello World!';
  }
}
