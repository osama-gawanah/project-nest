import {
  Controller,
  Post,
  Get,
  Patch,
  Body,
  Query,
  UseGuards,
  BadRequestException,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { Verify2FADto } from './dto/verify-2fa.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { ResendVerificationDto } from './dto/resend-verification.dto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { ResetPasswordWithTokenDto } from './dto/reset-password-with-token.dto';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { CurrentUser } from './decorators/current-user.decorator';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('register')
  async register(@Body() registerDto: RegisterDto) {
    return this.authService.register(registerDto);
  }

  @Post('login')
  async login(@Body() loginDto: LoginDto) {
    return this.authService.login(loginDto);
  }

  @Post('login/verify-2fa')
  async verify2FALogin(@Body() body: { tempToken: string; token: string }) {
    return this.authService.verify2FALogin(body.tempToken, {
      token: body.token,
    });
  }

  @UseGuards(JwtAuthGuard)
  @Get('profile')
  async getProfile(@CurrentUser() user: any) {
    return user;
  }

  @UseGuards(JwtAuthGuard)
  @Get('2fa/setup')
  async setup2FA(@CurrentUser() user: any) {
    return this.authService.setup2FA(user.userId);
  }

  @UseGuards(JwtAuthGuard)
  @Post('2fa/verify')
  async verify2FA(
    @CurrentUser() user: any,
    @Body() verify2FADto: Verify2FADto,
  ) {
    return this.authService.verify2FA(user.userId, verify2FADto);
  }

  @UseGuards(JwtAuthGuard)
  @Patch('2fa/disable')
  async disable2FA(@CurrentUser() user: any) {
    return this.authService.disable2FA(user.userId);
  }

  @Post('refresh')
  async refreshToken(@Body() refreshTokenDto: RefreshTokenDto) {
    return this.authService.refreshToken(refreshTokenDto);
  }

  @UseGuards(JwtAuthGuard)
  @Post('logout')
  async logout(@CurrentUser() user: any) {
    return this.authService.logout(user.userId || user.id);
  }

  @Get('verify-email')
  async verifyEmail(@Query('token') token: string) {
    if (!token) {
      throw new BadRequestException('Verification token is required');
    }
    return this.authService.verifyEmail(token);
  }

  @Post('resend-verification')
  async resendVerification(@Body() resendVerificationDto: ResendVerificationDto) {
    return this.authService.resendVerificationEmail(resendVerificationDto.email);
  }

  @Post('forgot-password')
  async forgotPassword(@Body() forgotPasswordDto: ForgotPasswordDto) {
    return this.authService.forgotPassword(forgotPasswordDto);
  }

  @Post('reset-password')
  async resetPassword(
    @Body() body: { token: string; password: string },
  ) {
    return this.authService.resetPasswordWithAccessToken(body.token, body.password);
  }

  @UseGuards(JwtAuthGuard)
  @Post('reset-password/authenticated')
  async resetPasswordAuthenticated(
    @CurrentUser() user: any,
    @Body() resetPasswordWithTokenDto: ResetPasswordWithTokenDto,
  ) {
    // For authenticated users, we can reset password directly
    const userId = user.userId || user.id || user.sub;
    return this.authService.resetPasswordAuthenticated(userId, resetPasswordWithTokenDto.password);
  }
}

