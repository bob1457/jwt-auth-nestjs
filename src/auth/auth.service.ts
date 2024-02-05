import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { SignInDto } from './dto/signIn.dto';
import { User } from './schemas/user.schema';
import { Model } from 'mongoose';
import * as bcrypt from 'bcrypt';
import { InjectModel } from '@nestjs/mongoose';
import * as crypto from 'crypto';

const AT_EXPIRE_TIME = 3600 * 1000 * 24;
const RT_EXPIRE_TIME = 3600 * 1000 * 24 * 7;
const AT_SECRET_KEY = 'secretKey';
const RT_SECRET_KEY = 'secretKey2';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name) private userModel: Model<User>,
    private jwtService: JwtService,
  ) {}

  async signIn(signInDto: SignInDto) {
    // const payload = { email: signInDto.email, password: signInDto.password };

    const user = await this.userModel.findOne({ email: signInDto.email });
    // console.log('user found', user);

    // check if user email verified
    if (!user.emailVerified) {
      throw new BadRequestException('Please verify your email');
    }

    if (user && bcrypt.compare(user.password, signInDto.password)) {
      const payload = {
        email: user.email,
        sub: user._id,
      };

      const access_token = this.jwtService.sign(payload, {
        secret: AT_SECRET_KEY,
        expiresIn: AT_EXPIRE_TIME,
      });

      const refresh_token = this.jwtService.sign(payload, {
        secret: RT_SECRET_KEY,
        expiresIn: RT_EXPIRE_TIME,
      });

      // update the refresh token in the database
      // ****************************
      // another consideration is return this refersh token, together with
      // the access token, to the client that then stored in local storage
      user.refreshToken = refresh_token;
      try {
        await user.save();
      } catch (error) {
        throw new Error('Error updating refresh token');
      }

      return {
        user,
        Tokens: {
          access_token,
          refresh_token,
        },
      };
    }
    // return new Error('Incorrect email or password');
    throw new UnauthorizedException();
  }

  async signUp(signInDto: SignInDto): Promise<any> {
    // check if the user already exists
    const user = await this.userModel.findOne({ email: signInDto.email });
    // console.log('existing user', user);
    if (user) {
      throw new BadRequestException('User already exists');
    }

    // hash password
    const hashedPassword = await bcrypt.hash(signInDto.password, 10);

    // create new user

    const newUser = new this.userModel({
      ...signInDto,
      password: hashedPassword,
    });

    return newUser.save();
  }

  async verifyEmail(token: string) {
    const user = await this.userModel.findOne({
      emailVerificaitonToken: token,
    });
    if (user) {
      user.emailVerified = true;
      user.emailVerificaitonToken = undefined;
      try {
        await user.save();
      } catch (error) {
        throw new Error('Error verifying email');
      }
    }

    throw new BadRequestException('Invalid token');
  }

  async forgotPassword(email: string) {
    const user = await this.userModel.findOne({ email });

    if (user) {
      // create a reset token
      const resetPasswordToken = crypto.randomBytes(32).toString('hex');
      const resetPasswordExpire = Date.now() + 3600000; // 60 minutes

      user.resetPasswordToken = resetPasswordToken;
      // user.resetPasswordExpire = resetPasswordExpiry;

      try {
        await this.userModel.findOneAndUpdate(
          { email: user.email },
          { resetPasswordToken, resetPasswordExpire },
        );
      } catch (error) {
        throw new Error('Error creating reset token');
      }
    }

    throw new BadRequestException('Invalid email');
  }

  async refreshToken(user: any) {
    try {
      const payload = {
        email: user.email,
        sub: user._id,
      };

      const access_token = this.jwtService.sign(payload, {
        secret: AT_SECRET_KEY,
        expiresIn: AT_EXPIRE_TIME,
      });

      const refresh_token = this.jwtService.sign(payload, {
        secret: RT_SECRET_KEY,
        expiresIn: RT_EXPIRE_TIME,
      });

      return {
        access_token,
        refresh_token,
      };
    } catch (error) {
      throw new UnauthorizedException();
    }
  }
}
