import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';
import { ConfigModule } from '@nestjs/config';
import { MongooseModule } from '@nestjs/mongoose';
import { UserModule } from './user/user.module';
import configuration from './config/configuration';
// process.env.MONGODB_URI

@Module({
  imports: [
    MongooseModule.forRoot(
      'mongodb://admin:password123@localhost:27017/authmon?authSource=admin',
      // `${process.env.MONGODB_URI}`,
    ),
    AuthModule,
    ConfigModule.forRoot({
      load: [configuration],
      envFilePath: '.env',
      isGlobal: true,
    }),
    UserModule,
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
