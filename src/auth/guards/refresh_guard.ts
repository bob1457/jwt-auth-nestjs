import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { Request } from 'express';

// const RT_SECRET_KEY = process.env.RT_SECRET_KEY; // 'secretKey2';

@Injectable()
export class RefreshJwtGuard implements CanActivate {
  constructor(
    private jwtService: JwtService,
    private configServie: ConfigService,
  ) {}
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();

    const token = this.extractTokenFromHeader(request);
    // console.log('coming token: ' + token);

    if (!token) throw new UnauthorizedException();

    try {
      const payload = await this.jwtService.verifyAsync(token, {
        secret: this.configServie.get<string>('RT_SECRET_KEY'), //RT_SECRET_KEY, //process.env.jwtRefreshTokenKey,
      });
      request['user'] = payload;
    } catch {
      throw new UnauthorizedException();
    }

    return true;
  }

  private extractTokenFromHeader(request: Request) {
    const [type, token] = request.headers.authorization?.split(' ') ?? [];
    return type === 'Refresh' ? token : undefined;
  }
}
