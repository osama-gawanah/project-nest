import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { UsersService } from '../../users/users.service';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(private usersService: UsersService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: process.env.JWT_SECRET || 'your-secret-key',
    });
  }

  async validate(payload: any) {
    // Support both 'sub' and 'id' in payload
    const userId = payload.sub || payload.id;
    if (!userId) {
      throw new UnauthorizedException('Invalid token payload');
    }

    const user = await this.usersService.findById(userId);
    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    // Convert Sequelize model to plain object if needed
    const userPlain = (user as any).toJSON ? (user as any).toJSON() : (user as any).dataValues || user;

    return {
      userId: userPlain.id,
      id: userPlain.id,
      email: userPlain.email,
      username: userPlain.username,
      role: userPlain.role,
    };
  }
}

