import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from './entities/user.entity';
import { Role } from './entities/role.entity';
import * as bcrypt from 'bcrypt';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
    @InjectRepository(Role)
    private roleRepository: Repository<Role>,
    private jwtService: JwtService,
  ) {}

  async validateUser(email: string, password: string): Promise<any> {
    const user = await this.userRepository.findOne({
      where: { email },
      relations: ['roles'],
    });

    if (user && user.passwordHash && await bcrypt.compare(password, user.passwordHash)) {
      const { passwordHash, ...result } = user;
      return result;
    }
    return null;
  }

  async validateSamlUser(profile: any): Promise<User> {
    const { email, name, nameID } = profile;
    
    let user = await this.userRepository.findOne({
      where: { email },
      relations: ['roles'],
    });

    if (!user) {
      // Create new user from SAML profile
      user = this.userRepository.create({
        email,
        name,
        samlNameId: nameID,
        isActive: true,
      });
      
      // Assign default analyst role
      const analystRole = await this.roleRepository.findOne({
        where: { name: 'analyst' },
      });
      
      if (analystRole) {
        user.roles = [analystRole];
      }
      
      user = await this.userRepository.save(user);
    } else {
      // Update last login
      user.lastLoginAt = new Date();
      await this.userRepository.save(user);
    }

    return user;
  }

  async login(user: any) {
    const payload = { 
      email: user.email, 
      sub: user.id,
      roles: user.roles?.map(role => role.type) || [],
    };
    
    return {
      access_token: this.jwtService.sign(payload),
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        roles: user.roles,
      },
    };
  }

  async findById(id: string): Promise<User | null> {
    return this.userRepository.findOne({
      where: { id },
      relations: ['roles'],
    });
  }
}
