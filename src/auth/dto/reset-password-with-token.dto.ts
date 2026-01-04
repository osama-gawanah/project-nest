import { IsString, MinLength } from 'class-validator';

export class ResetPasswordWithTokenDto {
  @IsString()
  @MinLength(6)
  password: string;
}

