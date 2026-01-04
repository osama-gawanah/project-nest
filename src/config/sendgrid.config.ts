import { registerAs } from '@nestjs/config';

export default registerAs('sendgrid', () => ({
  apiKey: process.env.SENDGRID_API_KEY || 'process.env.SENDGRID_API_KEY',
  fromEmail: process.env.SENDGRID_FROM_EMAIL || 'osama.jawanh@gmail.com',
  fromName: process.env.SENDGRID_FROM_NAME || 'Osama Husam',
}));

