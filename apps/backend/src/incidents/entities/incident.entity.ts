import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn, UpdateDateColumn, OneToMany } from 'typeorm';
import { Artifact } from '../../artifacts/entities/artifact.entity';
import { Timeline } from '../../timelines/entities/timeline.entity';
import { Report } from '../../reports/entities/report.entity';

export enum IncidentStatus {
  OPEN = 'open',
  INVESTIGATING = 'investigating',
  CONTAINED = 'contained',
  RESOLVED = 'resolved',
  CLOSED = 'closed',
}

export enum IncidentSeverity {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CRITICAL = 'critical',
}

@Entity('incidents')
export class Incident {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column()
  title: string;

  @Column('text', { nullable: true })
  description?: string;

  @Column({
    type: 'enum',
    enum: IncidentStatus,
    default: IncidentStatus.OPEN,
  })
  status: IncidentStatus;

  @Column({
    type: 'enum',
    enum: IncidentSeverity,
    default: IncidentSeverity.MEDIUM,
  })
  severity: IncidentSeverity;

  @Column({ nullable: true })
  assigneeId?: string;

  @Column({ nullable: true })
  detectedAt?: Date;

  @Column({ nullable: true })
  containedAt?: Date;

  @Column({ nullable: true })
  resolvedAt?: Date;

  @Column('simple-array', { default: '' })
  tags: string[];

  @Column('jsonb', { nullable: true })
  metadata?: Record<string, any>;

  @OneToMany(() => Artifact, artifact => artifact.incident)
  artifacts: Artifact[];

  @OneToMany(() => Timeline, timeline => timeline.incident)
  timelines: Timeline[];

  @OneToMany(() => Report, report => report.incident)
  reports: Report[];

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;
}
