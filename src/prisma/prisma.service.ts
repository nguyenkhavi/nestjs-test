import { Injectable, INestApplication, OnModuleInit } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';

@Injectable()
export class PrismaService extends PrismaClient implements OnModuleInit {
  constructor() {
    super({
      log: [],
    });
  }

  async onModuleInit() {
    await this.$connect();
    console.log('Connected database', process.env.DATABASE_URL);
    this.$use(async (params, next) => {
      const result = await next(params);
      return result;
    });
  }

  async enableShutdownHooks(app: INestApplication) {
    this.$on('beforeExit', async () => {
      console.log('Disconnecting database');
      await this.$disconnect();
      await app.close();
    });
  }
}
