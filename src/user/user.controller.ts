import { Controller, Get, UseGuards } from '@nestjs/common';
import { User } from 'src/auth/schemas/user.schema';
import { UserService } from './user.service';
import { JwtGuard } from 'src/auth/guards/jwt_guard';

@Controller('user')
export class UserController {
  constructor(private userService: UserService) {}

  @UseGuards(JwtGuard)
  @Get()
  async getUsers(): Promise<User[]> {
    return this.userService.getAllUsers();
  }
}
