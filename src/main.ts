import { NestFactory } from '@nestjs/core';
import { ValidationPipe } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AppModule } from './app.module';
import { getConnectionToken } from '@nestjs/sequelize';
import { Sequelize } from 'sequelize-typescript';
import { TransformInterceptor } from './common/interceptors/transform.interceptor';
import { HttpExceptionFilter } from './common/filters/http-exception.filter';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const configService = app.get(ConfigService);

  // Global prefix
  const apiPrefix = configService.get<string>('app.apiPrefix', 'api');
  app.setGlobalPrefix(apiPrefix);

  // Global pipes
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
      transformOptions: {
        enableImplicitConversion: true,
      },
    }),
  );

  // Global interceptors
  app.useGlobalInterceptors(new TransformInterceptor());

  // Global filters
  app.useGlobalFilters(new HttpExceptionFilter());

  // Sync database schema in development (adds missing columns, doesn't drop existing data)
  if (configService.get<string>('app.nodeEnv') !== 'production') {
    try {
      const sequelize = app.get<Sequelize>(getConnectionToken());
      if (sequelize) {
        // Use alter: true to add missing columns without dropping data
        await sequelize.sync({ alter: true });
        console.log('Database schema synchronized successfully');
      }
    } catch (error) {
      console.error('Error synchronizing database:', error);
      console.log('You may need to manually add the missing column. See fix-database.sql');
    }
  }

  const port = configService.get<number>('app.port', 3000);
  await app.listen(port);
  console.log(`Application is running on: http://localhost:${port}/${apiPrefix}`);
}
bootstrap();
