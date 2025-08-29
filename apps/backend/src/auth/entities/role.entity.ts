import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn, UpdateDateColumn, ManyToMany } from 'typeorm';
import { User } from './user.entity';

export enum RoleType {
  IR_LEAD = 'ir_lead',
  ANALYST = 'analyst',
  REVIEWER = 'reviewer',
  ADMIN = 'admin',
}

@Entity('roles')
export class Role {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ unique: true })
  name: string;

  @Column({
    type: 'enum',
    enum: RoleType,
  })
  type: RoleType;

  @Column({ nullable: true })
  description?: string;

  @Column('simple-array', { default: '' })
  permissions: string[];

  @ManyToMany(() => User, user => user.roles)
  users: User[];

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;
}
