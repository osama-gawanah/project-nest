import {
  Injectable,
  BadRequestException,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import * as speakeasy from 'speakeasy';
import * as QRCode from 'qrcode';
import { UsersService } from '../users/users.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { Verify2FADto } from './dto/verify-2fa.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { UserRole } from '../users/schemas/user.schema';

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
  ) {}

  async register(registerDto: RegisterDto) {
    try {
      const { email, password, username } = registerDto;

      const existingUser = await this.usersService.findByEmail(email);
      if (existingUser) {
        throw new BadRequestException('User already exists');
      }

      const hashedPassword = await bcrypt.hash(password, 10);

      const user = await this.usersService.create({
        email,
        password: hashedPassword,
        username,
        role: UserRole.USER,
        isTwoFactorEnabled: false,
      });

      // Convert Sequelize model to plain object
      const userPlain = user.toJSON ? user.toJSON() : (user as any).dataValues || user;
      const { password: _, ...result } = userPlain;
      return result;
    } catch (error: any) {
      if (error instanceof BadRequestException) {
        throw error;
      }
      // Handle Sequelize unique constraint errors
      if (error?.name === 'SequelizeUniqueConstraintError' || error?.parent?.code === 'ER_DUP_ENTRY') {
        throw new BadRequestException('User with this email already exists');
      }
      // Log the actual error for debugging
      console.error('Registration error:', error);
      throw new BadRequestException('Failed to register user: ' + (error?.message || 'Unknown error'));
    }
  }

  async validateUser(email: string, password: string) {
    try {
      const isDevelopment = process.env.NODE_ENV !== 'production';
      
      if (isDevelopment) {
        console.log(`[validateUser] Attempting to find user with email: ${email}`);
      }
      
      const user = await this.usersService.findByEmail(email);
      if (!user) {
        if (isDevelopment) {
          console.log(`[validateUser] User not found with email: ${email}`);
        }
        return null;
      }

      if (isDevelopment) {
        console.log(`[validateUser] User found: ID=${user.id}, Email=${user.email}`);
      }

      // Get password from Sequelize model - try multiple ways
      let userPassword: string | undefined;
      
      // Try direct access
      if ((user as any).password) {
        userPassword = (user as any).password;
      }
      // Try dataValues
      else if ((user as any).dataValues?.password) {
        userPassword = (user as any).dataValues.password;
      }
      // Try get() method
      else if (typeof (user as any).get === 'function') {
        userPassword = (user as any).get('password');
      }
      // Try toJSON
      else if (typeof (user as any).toJSON === 'function') {
        const plain = (user as any).toJSON();
        userPassword = plain.password;
      }

      if (!userPassword) {
        console.error('[validateUser] User found but password field is missing');
        if (isDevelopment) {
          console.error('[validateUser] User object keys:', Object.keys(user));
          console.error('[validateUser] User dataValues:', (user as any).dataValues);
        }
        return null;
      }

      if (isDevelopment) {
        console.log(`[validateUser] Comparing passwords...`);
      }
      
      const isPasswordValid = await bcrypt.compare(password, userPassword);
      
      if (isDevelopment) {
        console.log(`[validateUser] Password valid: ${isPasswordValid}`);
      }

      if (!isPasswordValid) {
        return null;
      }

      // Convert Sequelize model to plain object
      let userPlain: any;
      if (typeof (user as any).toJSON === 'function') {
        userPlain = (user as any).toJSON();
      } else if ((user as any).dataValues) {
        userPlain = (user as any).dataValues;
      } else if (typeof (user as any).get === 'function') {
        userPlain = (user as any).get({ plain: true });
      } else {
        userPlain = user;
      }

      const { password: _, ...result } = userPlain;
      
      if (isDevelopment) {
        console.log(`[validateUser] User validated successfully: ID=${result.id}`);
      }
      
      return result;
    } catch (error: any) {
      console.error('[validateUser] Error:', error);
      if (process.env.NODE_ENV !== 'production') {
        console.error('[validateUser] Error stack:', error?.stack);
      }
      return null;
    }
  }

  async login(loginDto: LoginDto) {
    try {
      const isDevelopment = process.env.NODE_ENV !== 'production';
      
      if (isDevelopment) {
        console.log('[login] Starting login process');
      }
      
      const { email, password } = loginDto;

      if (!email || !password) {
        throw new UnauthorizedException('Email and password are required');
      }

      if (isDevelopment) {
        console.log(`[login] Validating user: ${email}`);
      }
      
      const user = await this.validateUser(email, password);
      
      if (!user) {
        if (isDevelopment) {
          console.log(`[login] User validation failed for: ${email}`);
        }
        throw new UnauthorizedException('Invalid email or password');
      }

      if (isDevelopment) {
        console.log(`[login] User validated: ID=${user.id}, Email=${user.email}`);
      }

      // Ensure username exists (fallback to email if not)
      const username = user.username || user.email?.split('@')[0] || 'user';

      // If 2FA is enabled, return temporary token
      if (user.isTwoFactorEnabled) {
        if (isDevelopment) {
          console.log(`[login] 2FA enabled for user: ${user.id}`);
        }
        const tempToken = this.jwtService.sign(
          { sub: user.id, email: user.email, requires2FA: true },
          { expiresIn: '5m' },
        );

        return {
          requires2FA: true,
          tempToken,
        };
      }

      // Normal login without 2FA
      if (isDevelopment) {
        console.log(`[login] Creating JWT tokens for user: ${user.id}`);
      }
      
      const payload = { 
        id: user.id,
        sub: user.id, 
        email: user.email, 
        role: user.role 
      };
      
      // Generate access token (short-lived)
      const accessToken = this.jwtService.sign(payload, { expiresIn: '15m' });
      
      // Generate refresh token (long-lived)
      const refreshToken = this.jwtService.sign(
        { sub: user.id, type: 'refresh' },
        { expiresIn: '7d' }
      );

      // Save refresh token to database
      await this.usersService.update(user.id, {
        refreshToken: refreshToken,
      });

      if (isDevelopment) {
        console.log(`[login] Login successful for user: ${user.id}`);
      }

      return {
        accessToken,
        refreshToken,
        user: {
          id: user.id,
          email: user.email,
          username: username,
          role: user.role,
        },
      };
    } catch (error: any) {
      if (error instanceof UnauthorizedException) {
        throw error;
      }
      // Log the actual error for debugging
      console.error('[login] Login error:', error);
      if (process.env.NODE_ENV !== 'production') {
        console.error('[login] Error message:', error?.message);
        console.error('[login] Error stack:', error?.stack);
      }
      throw new UnauthorizedException('Login failed: ' + (error?.message || 'Unknown error'));
    }
  }

  async setup2FA(userId: string) {
    const user = await this.usersService.findById(userId);
    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    if (user.isTwoFactorEnabled) {
      throw new BadRequestException('2FA is already enabled');
    }

    const secret = speakeasy.generateSecret({
      name: `NestJS App (${user.email})`,
    });

    await this.usersService.update(userId, {
      twoFactorSecret: secret.base32,
    });

    if (!secret.otpauth_url) {
      throw new BadRequestException('Failed to generate 2FA secret');
    }

    const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);

    return {
      secret: secret.base32,
      qrCode: qrCodeUrl,
    };
  }

  async verify2FA(userId: string, verify2FADto: Verify2FADto) {
    const user = await this.usersService.findById(userId);
    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    if (!user.twoFactorSecret) {
      throw new BadRequestException(
        '2FA secret not found. Please setup 2FA first.',
      );
    }

    const verified = speakeasy.totp.verify({
      secret: user.twoFactorSecret,
      encoding: 'base32',
      token: verify2FADto.token,
      window: 2,
    });

    if (!verified) {
      throw new UnauthorizedException('Invalid 2FA token');
    }

    await this.usersService.update(userId, {
      isTwoFactorEnabled: true,
    });

    return { message: '2FA enabled successfully' };
  }

  async verify2FALogin(tempToken: string, verify2FADto: Verify2FADto) {
    try {
      const payload = this.jwtService.verify(tempToken);

      if (!payload.requires2FA) {
        throw new UnauthorizedException('Invalid token');
      }

      const user = await this.usersService.findById(payload.sub);
      if (!user || !user.isTwoFactorEnabled || !user.twoFactorSecret) {
        throw new UnauthorizedException('User not found or 2FA not enabled');
      }

      const verified = speakeasy.totp.verify({
        secret: user.twoFactorSecret,
        encoding: 'base32',
        token: verify2FADto.token,
        window: 2,
      });

      if (!verified) {
        throw new UnauthorizedException('Invalid 2FA token');
      }

      const finalToken = this.jwtService.sign({
        sub: user.id,
        email: user.email,
        role: user.role,
      }, { expiresIn: '15m' });

      // Generate refresh token
      const refreshToken = this.jwtService.sign(
        { sub: user.id, type: 'refresh' },
        { expiresIn: '7d' }
      );

      // Save refresh token to database
      await this.usersService.update(user.id, {
        refreshToken: refreshToken,
      });

      return {
        accessToken: finalToken,
        refreshToken,
        user: {
          id: user.id,
          email: user.email,
          username: user.username,
          role: user.role,
        },
      };
    } catch (error) {
      throw new UnauthorizedException('Invalid or expired token');
    }
  }

  async disable2FA(userId: string) {
    const user = await this.usersService.findById(userId);
    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    await this.usersService.update(userId, {
      isTwoFactorEnabled: false,
      twoFactorSecret: undefined,
    });

    return { message: '2FA disabled successfully' };
  }

  async refreshToken(refreshTokenDto: RefreshTokenDto) {
    try {
      const { refreshToken } = refreshTokenDto;

      if (!refreshToken) {
        throw new UnauthorizedException('Refresh token is required');
      }

      // Verify refresh token
      let payload: any;
      try {
        payload = this.jwtService.verify(refreshToken);
      } catch (error) {
        throw new UnauthorizedException('Invalid or expired refresh token');
      }

      // Check if token is a refresh token
      if (payload.type !== 'refresh') {
        throw new UnauthorizedException('Invalid token type');
      }

      // Find user by ID and verify refresh token matches
      const user = await this.usersService.findById(payload.sub);
      if (!user) {
        throw new UnauthorizedException('User not found');
      }

      // Get stored refresh token
      const userPlain = (user as any).toJSON ? (user as any).toJSON() : (user as any).dataValues || user;
      const storedRefreshToken = userPlain.refreshToken;

      if (!storedRefreshToken || storedRefreshToken !== refreshToken) {
        throw new UnauthorizedException('Invalid refresh token');
      }

      // Generate new access token
      const newPayload = {
        id: user.id,
        sub: user.id,
        email: user.email,
        role: userPlain.role,
      };

      const accessToken = this.jwtService.sign(newPayload, { expiresIn: '15m' });

      // Optionally rotate refresh token for security
      const newRefreshToken = this.jwtService.sign(
        { sub: user.id, type: 'refresh' },
        { expiresIn: '7d' }
      );

      // Update refresh token in database
      await this.usersService.update(user.id, {
        refreshToken: newRefreshToken,
      });

      return {
        accessToken,
        refreshToken: newRefreshToken,
        user: {
          id: user.id,
          email: user.email,
          username: userPlain.username,
          role: userPlain.role,
        },
      };
    } catch (error: any) {
      if (error instanceof UnauthorizedException) {
        throw error;
      }
      console.error('[refreshToken] Error:', error);
      throw new UnauthorizedException('Failed to refresh token: ' + (error?.message || 'Unknown error'));
    }
  }

  async logout(userId: string) {
    try {
      // Remove refresh token from database
      await this.usersService.update(userId, {
        refreshToken: undefined,
      });

      return { message: 'Logged out successfully' };
    } catch (error: any) {
      console.error('[logout] Error:', error);
      throw new BadRequestException('Failed to logout: ' + (error?.message || 'Unknown error'));
    }
  }
}

