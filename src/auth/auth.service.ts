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
import { ConfigService } from '@nestjs/config';
import { ForgotPasswordDto } from './dto/forgotPassword.dto';
import { NewPassWordDto } from './dto/newPassword.dto';

// const AT_EXPIRE_TIME = process.env.AT_EXPIRE_TIME; // 3600 * 1000 * 24;
// const RT_EXPIRE_TIME = process.env.RT_EXPIRE_TIME; //3600 * 1000 * 24 * 7;
// const AT_SECRET_KEY = process.env.AT_SECRET_KEY; // 'secretKey';
// const RT_SECRET_KEY = process.env.RT_SECRET_KEY; //'secretKey2';

const AT_EXPIRE_TIME = '15m'; //3600 * 1000 * 24;
const RT_EXPIRE_TIME = '7d'; //3600 * 1000 * 24 * 7;
// const AT_SECRET_KEY = 'secretKey';
// const RT_SECRET_KEY = 'secretKey2';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name) private userModel: Model<User>,
    private jwtService: JwtService,
    private readonly configService: ConfigService,
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
        secret: this.configService.get<string>('AT_SECRET_KEY'), // AT_SECRET_KEY,
        expiresIn: AT_EXPIRE_TIME, //this.configService.get<number>('AT_EXPIRE_TIME'), //,
      });

      const decodedToken = this.jwtService.decode(access_token);
      console.log('generatedToken', decodedToken);

      const access_token_expires_in = decodedToken.exp;

      const refresh_token = this.jwtService.sign(payload, {
        secret: this.configService.get<string>('RT_SECRET_KEY'), //RT_SECRET_KEY,
        expiresIn: RT_EXPIRE_TIME, //this.configService.get<number>('RT_EXPIRE_TIME'), //
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
          access_token_expires_in,
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

    // generate email verification token and send to user's email
    const emailVerificaitonToken = crypto.randomBytes(32).toString('hex');
    const emailVerificationUrl =
      'http://localhost:5000/verifyemail/' + emailVerificaitonToken;
    // create new user

    const newUser = new this.userModel({
      ...signInDto,
      password: hashedPassword,
      emailVerificaitonToken,
    });

    console.log(emailVerificationUrl);

    // send email to user
    // await sendEmail({})

    return newUser.save();
  }

  async verifyEmail(token: string) {
    // console.log('token received', token);

    const user = await this.userModel.findOne({
      emailVerificaitonToken: token,
    });

    // console.log('found user', user);
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

  async forgotPassword(email: ForgotPasswordDto) {
    console.log('recived email', email.email);
    const user = await this.userModel.findOne({ email: email.email });
    console.log('found user', user);

    if (!user) throw new BadRequestException('Invalid email');

    const resetPasswordToken = crypto.randomBytes(32).toString('hex');
    const resetPasswordExpire = Date.now() + 3600000; // 60 minutes

    user.resetPasswordToken = resetPasswordToken;
    // user.resetPasswordExpire = resetPasswordExpiry;

    try {
      await this.userModel.findOneAndUpdate(
        { email: user.email },
        { resetPasswordToken, resetPasswordExpire },
      );
      // send the reset password token to the user's email
    } catch (error) {
      throw new Error('Error creating reset token');
    }
  }

  async resetPassword(token: string, password: NewPassWordDto) {
    console.log('token received', token);
    console.log('new password', password.password);
    const user = await this.userModel.findOne({
      resetPasswordToken: token,
      resetPasswordExpire: { $gt: Date.now() },
    });

    if (!user) {
      throw new BadRequestException('Invalid or expired token');
    }

    const hashedPassword = await bcrypt.hash(password.password, 10);

    user.password = hashedPassword;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpire = undefined;

    try {
      await user.save();
    } catch (error) {
      throw new Error('Error resetting password');
    }
  }

  async refreshToken(user: any) {
    try {
      const payload = {
        email: user.email,
        sub: user._id,
      };

      const access_token = this.jwtService.sign(payload, {
        secret: this.configService.get<string>('AT_SECRET_KEY'),
        expiresIn: AT_EXPIRE_TIME,
      });

      const refresh_token = this.jwtService.sign(payload, {
        secret: this.configService.get<string>('RT_SECRET_KEY'),
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
