import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import sgMail from '@sendgrid/mail';

@Injectable()
export class EmailService {
  private readonly logger = new Logger(EmailService.name);
  private readonly fromEmail: string;
  private readonly fromName: string;

  constructor(private configService: ConfigService) {
    const apiKey = this.configService.get<string>('sendgrid.apiKey');
    if (!apiKey) {
      this.logger.warn('SENDGRID_API_KEY is not set. Email functionality will be disabled.');
    } else {
      sgMail.setApiKey(apiKey);
    }
    this.fromEmail = this.configService.get<string>('sendgrid.fromEmail') || 'noreply@example.com';
    this.fromName = this.configService.get<string>('sendgrid.fromName') || 'NestJS App';
  }

  async sendVerificationEmail(to: string, token: string, username: string): Promise<void> {
    const apiKey = this.configService.get<string>('sendgrid.apiKey');
    if (!apiKey) {
      this.logger.error('Cannot send email: SENDGRID_API_KEY is not configured');
      throw new Error('Email service is not configured');
    }

    if (!this.fromEmail || this.fromEmail === 'noreply@example.com') {
      this.logger.error('Cannot send email: SENDGRID_FROM_EMAIL is not properly configured');
      throw new Error('From email address is not configured. Please set SENDGRID_FROM_EMAIL in your environment variables.');
    }

    const appUrl = process.env.APP_URL || 'http://localhost:3000';
    const verificationUrl = `${appUrl}/api/auth/verify-email?token=${token}`;

    const msg = {
      to,
      from: this.fromEmail,
      subject: 'Verify your email address',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #333;">Hello ${username}!</h2>
          <p>Thank you for registering. Please verify your email address by clicking the button below:</p>
          <div style="text-align: center; margin: 30px 0;">
            <a href="${verificationUrl}" 
               style="background-color: #007bff; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; display: inline-block;">
              Verify Email
            </a>
          </div>
          <p>Or copy and paste this link into your browser:</p>
          <p style="color: #666; word-break: break-all;">${verificationUrl}</p>
          <p style="color: #999; font-size: 12px; margin-top: 30px;">
            This link will expire in 24 hours. If you didn't create an account, please ignore this email.
          </p>
        </div>
      `,
      text: `
        Hello ${username}!
        
        Thank you for registering. Please verify your email address by visiting this link:
        ${verificationUrl}
        
        This link will expire in 24 hours. If you didn't create an account, please ignore this email.
      `,
    };

    try {
      await sgMail.send(msg);
      this.logger.log(`Verification email sent to ${to}`);
    } catch (error: any) {
      this.logger.error(`Failed to send verification email to ${to}:`, error);
      if (error.response) {
        this.logger.error('SendGrid error response:', JSON.stringify(error.response.body, null, 2));
        throw new Error(`Failed to send verification email: ${error.response.body?.errors?.[0]?.message || error.message}`);
      }
      throw new Error(`Failed to send verification email: ${error.message || 'Unknown error'}`);
    }
  }

  async sendPasswordResetEmail(to: string, token: string, username: string): Promise<void> {
    const apiKey = this.configService.get<string>('sendgrid.apiKey');
    if (!apiKey) {
      this.logger.error('Cannot send email: SENDGRID_API_KEY is not configured');
      throw new Error('Email service is not configured');
    }

    const appUrl = process.env.APP_URL || 'http://localhost:3000';
    const resetUrl = `${appUrl}/api/auth/reset-password?token=${token}`;

    const msg = {
      to,
      from: {
        email: this.fromEmail,
        name: this.fromName,
      },
      subject: 'Reset your password',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #333;">Hello ${username}!</h2>
          <p>You requested to reset your password. Click the button below to reset it:</p>
          <div style="text-align: center; margin: 30px 0;">
            <a href="${resetUrl}" 
               style="background-color: #dc3545; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; display: inline-block;">
              Reset Password
            </a>
          </div>
          <p>Or copy and paste this link into your browser:</p>
          <p style="color: #666; word-break: break-all;">${resetUrl}</p>
          <p style="color: #999; font-size: 12px; margin-top: 30px;">
            This link will expire in 1 hour. If you didn't request a password reset, please ignore this email.
          </p>
        </div>
      `,
      text: `
        Hello ${username}!
        
        You requested to reset your password. Visit this link to reset it:
        ${resetUrl}
        
        This link will expire in 1 hour. If you didn't request a password reset, please ignore this email.
      `,
    };

    try {
      await sgMail.send(msg);
      this.logger.log(`Password reset email sent to ${to}`);
    } catch (error: any) {
      this.logger.error(`Failed to send password reset email to ${to}:`, error);
      if (error.response) {
        this.logger.error('SendGrid error response:', JSON.stringify(error.response.body, null, 2));
        throw new Error(`Failed to send password reset email: ${error.response.body?.errors?.[0]?.message || error.message}`);
      }
      throw new Error(`Failed to send password reset email: ${error.message || 'Unknown error'}`);
    }
  }
}

