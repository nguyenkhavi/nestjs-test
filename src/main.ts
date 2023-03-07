import { ConfigService } from './config/config.service';
import { NestFactory } from '@nestjs/core';

import {
  FastifyAdapter,
  NestFastifyApplication,
} from '@nestjs/platform-fastify';

import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { AppModule } from './app.module';
import { PrismaService } from './prisma/prisma.service';
import { ErrorsInterceptor } from './interceptor/error.interceptor';
import { TransformResponseInterceptor } from './interceptor/transform-response.interceptor';
import { patchNestjsSwagger, ZodValidationPipe } from '@anatine/zod-nestjs';

async function bootstrap() {
  const adapter = new FastifyAdapter({ logger: false });

  const options = {
    origin: true,
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    preflightContinue: false,
    optionsSuccessStatus: 204,
    credentials: true,
    allowedHeaders: [
      'Access-Control-Allow-Origin',
      'Origin',
      'X-Requested-With',
      'Accept',
      'Content-Type',
      'Authorization',
    ],
  };

  const app = await NestFactory.create<NestFastifyApplication>(
    AppModule,
    adapter,
  );

  const configService = app.get<ConfigService>(ConfigService);

  // eslint-disable-next-line @typescript-eslint/no-var-requires
  app.register(require('@fastify/cors'), options);

  app.setGlobalPrefix(configService.getOrThrow('app.apiPrefix'), {
    exclude: ['/'],
  });

  app.useGlobalInterceptors(new TransformResponseInterceptor());
  app.useGlobalInterceptors(new ErrorsInterceptor());
  app.useGlobalPipes(new ZodValidationPipe());

  const config = new DocumentBuilder()
    .setTitle('Web3asy API')
    .setDescription('Web3asy API')
    .setVersion('1.0')
    .addBearerAuth()
    .build();

  patchNestjsSwagger();
  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('docs', app, document);

  await app.listen(configService.get('app.port') as string, '0.0.0.0');

  const prismaService = app.get(PrismaService);
  await prismaService.enableShutdownHooks(app);
  console.log(`Web3asy service listening on ${await app.getUrl()}/docs`);
}

bootstrap();
