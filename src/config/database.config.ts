import { registerAs } from '@nestjs/config';
import * as mysql2 from 'mysql2';

export default registerAs('database', () => ({
  dialect: 'mysql',
  dialectModule: mysql2,
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT || '3306', 10),
  username: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '1234',
  database: process.env.DB_NAME || 'your_database_name',
  autoLoadModels: true,
  logging: process.env.NODE_ENV === 'development' ? console.log : false,
}));

