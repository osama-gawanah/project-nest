import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { EmailService } from './email.service';
import sendgridConfig from '../../config/sendgrid.config';

@Module({
  imports: [ConfigModule.forFeature(sendgridConfig)],
  providers: [EmailService],
  exports: [EmailService],
})
export class EmailModule {}

