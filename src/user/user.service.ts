import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User } from 'src/auth/schemas/user.schema';

@Injectable()
export class UserService {
  constructor(@InjectModel(User.name) private userModel: Model<User>) {}

  async getAllUsers() {
    const users = await this.userModel.find();
    users.forEach((user) => {
      user.password = null;
      user.emailVerified = null;
      user.refreshToken = null;
    });
    return users;
  }
}
