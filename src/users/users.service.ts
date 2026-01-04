import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from './schemas/user.schema';

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
  ) {}

  async create(userData: Partial<User>): Promise<User> {
    const user = this.userRepository.create(userData);
    return this.userRepository.save(user);
  }

  async findByEmail(email: string): Promise<User | null> {
    try {
      return this.userRepository.findOne({
        where: { email },
      });
    } catch (error) {
      console.error('[UsersService] Error finding user by email:', error);
      return null;
    }
  }

  async findById(id: string | number): Promise<User | null> {
    const userId = typeof id === 'string' ? parseInt(id, 10) : id;
    return this.userRepository.findOne({
      where: { id: userId },
    });
  }

  async update(id: string | number, updateData: Partial<User>): Promise<User | null> {
    const userId = typeof id === 'string' ? parseInt(id, 10) : id;
    await this.userRepository.update(userId, updateData);
    return this.findById(userId);
  }
}
