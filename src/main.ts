import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  app.enableCors({
    origin: process.env.FRONTEND_URL || '*',
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  });

  const port = process.env.PORT || 3001;
  await app.listen(port);
  console.log(`tasket-auth running on port ${port}`);
  console.log(`  Authorization server: ${process.env.BASE_URL}/.well-known/oauth-authorization-server`);
  console.log(`  JWKS:                 ${process.env.BASE_URL}/.well-known/jwks.json`);
  console.log(`  Google login:         ${process.env.BASE_URL}/auth/google`);
}
bootstrap();
