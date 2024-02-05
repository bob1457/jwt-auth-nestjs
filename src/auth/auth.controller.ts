import { Controller, Post, Body, Request, UseGuards } from '@nestjs/common';
import { SignUpDto } from './dto/signup.dto';
import { AuthService } from './auth.service';
import { SignInDto } from './dto/signIn.dto';
import { ApiBearerAuth } from '@nestjs/swagger';
import { RefreshJwtGuard } from './guards/refresh_guard';

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

  @Post('refresh')
  @UseGuards(RefreshJwtGuard)
  @ApiBearerAuth('JWT-auth')
  async refresh(@Request() req) {
    // console.log('request', req.user);
    return await this.authService.refreshToken(req.user);
  }
}
