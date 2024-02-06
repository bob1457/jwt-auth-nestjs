import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
// import { JwtModule, JwtService } from '@nestjs/jwt';
import { MongooseModule } from '@nestjs/mongoose';
import { User, UserSchema } from './schemas/user.schema';
import { JwtService } from '@nestjs/jwt';
// import { ConfigModule } from '@nestjs/config';
// import configuration from 'src/config/configuration';

@Module({
  imports: [
    // ConfigModule.forRoot({
    //   isGlobal: true,
    //   load: [configuration],
    // }),
    MongooseModule.forFeature([{ name: User.name, schema: UserSchema }]),
    // JwtModule.register({
    //   secret: process.env.AT_SECRET_KEY,
    //   signOptions: { expiresIn: process.env.AT_EXPIRE_TIME },
    // }),
  ],
  controllers: [AuthController],
  providers: [AuthService, JwtService],
})
export class AuthModule {}
