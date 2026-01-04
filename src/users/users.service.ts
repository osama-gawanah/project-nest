import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/sequelize';
import { User } from './schemas/user.schema';

@Injectable()
export class UsersService {
  constructor(
    @InjectModel(User)
    private userModel: typeof User,
  ) {}

  async create(userData: Partial<User>): Promise<User> {
    return this.userModel.create(userData as any);
  }

  async findByEmail(email: string): Promise<User | null> {
    try {
      const user = await this.userModel.findOne({ 
        where: { email },
        raw: false, // Return Sequelize model instance, not plain object
      });
      return user;
    } catch (error) {
      console.error('[UsersService] Error finding user by email:', error);
      return null;
    }
  }

  async findById(id: string | number): Promise<User | null> {
    return this.userModel.findByPk(typeof id === 'string' ? parseInt(id) : id);
  }

  async update(id: string | number, updateData: Partial<User>): Promise<User | null> {
    const userId = typeof id === 'string' ? parseInt(id) : id;
    const user = await this.userModel.findByPk(userId);
    if (!user) {
      return null;
    }
    await user.update(updateData);
    return user;
  }
}
