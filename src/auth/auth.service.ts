import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { SignInDto } from './dto/signIn.dto';
import { User } from './schemas/user.schema';
import { Model } from 'mongoose';
import * as bcrypt from 'bcrypt';
import { InjectModel } from '@nestjs/mongoose';

const EXPIRE_TIME = 20 * 1000;
const SECRET_KEY = 'secretKey';

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

    if (user && bcrypt.compare(user.password, signInDto.password)) {
      const payload = {
        email: user.email,
        sub: user._id,
      };

      return {
        user,
        Tokens: {
          access_token: this.jwtService.sign(payload, {
            secret: SECRET_KEY,
            expiresIn: EXPIRE_TIME,
          }),
          refresh_token: this.jwtService.sign(payload, {
            secret: SECRET_KEY,
            expiresIn: EXPIRE_TIME,
          }),
        },
      };
    }
    return new Error('Incorrect email or password');
  }

  async signUp(signInDto: SignInDto) {
    // check if the user already exists
    const user = await this.userModel.findOne({ email: signInDto.email });
    // console.log('existing user', user);
    if (user) {
      throw new Error('User already exists');
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
}
