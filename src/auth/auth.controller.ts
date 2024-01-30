import { Controller, Post, Body } from '@nestjs/common';
import { SignUpDto } from './dto/signup.dto';
import { AuthService } from './auth.service';
import { SignInDto } from './dto/signIn.dto';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('signup')
  signup(@Body() _signupDto: SignUpDto) {
    return this.authService.signUp(_signupDto);
  }

  @Post('signin')
  signin(@Body() _signinDto: SignInDto) {
    return this.authService.signIn(_signinDto);
  }
}
