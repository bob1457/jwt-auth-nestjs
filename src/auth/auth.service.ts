import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { SignInDto } from './dto/signIn.dto';
import { User } from './schemas/user.schema';
import { Model } from 'mongoose';
import * as bcrypt from 'bcrypt';
import { InjectModel } from '@nestjs/mongoose';

const EXPIRE_TIME = 20 * 1000;

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name) private userModel: Model<User>,
    private jwtService: JwtService,
  ) {}

  async signIn(signInDto: SignInDto) {
    const payload = { email: signInDto.email, password: signInDto.password };
    return {
      access_token: this.jwtService.sign(payload, {
        expiresIn: EXPIRE_TIME,
      }),
    };
  }

  async signUp(signInDto: SignInDto) {
    // check if the user already exists
    const user = this.userModel.findOne({ email: signInDto.email });
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
