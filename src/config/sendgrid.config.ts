import { registerAs } from '@nestjs/config';
// apiKey: process.env.SENDGRID_API_KEY || 'process.env.SENDGRID_API_KEY',

export default registerAs('sendgrid', () => {
  const apiKey = process.env.SENDGRID_API_KEY;
  if (!apiKey) {
    throw new Error('SENDGRID_API_KEY environment variable is required');
  }

  return {
    apiKey,
    fromEmail: process.env.SENDGRID_FROM_EMAIL || 'osama.jawanh@gmail.com',
    fromName: process.env.SENDGRID_FROM_NAME || 'Osama Husam',
  };
});

