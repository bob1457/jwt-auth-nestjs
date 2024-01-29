import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ConfigService } from '@nestjs/config';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  app.enableCors();

  const configService = app.get(ConfigService);
  const PORT = configService.get<number>('port');
  await app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
}


bootstrap();
