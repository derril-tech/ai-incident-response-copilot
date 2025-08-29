import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn, UpdateDateColumn, ManyToOne, JoinColumn } from 'typeorm';
import { Timeline } from './timeline.entity';

export enum EventType {
  ALERT = 'alert',
  LOG_ENTRY = 'log_entry',
  USER_ACTION = 'user_action',
  SYSTEM_EVENT = 'system_event',
  NETWORK_EVENT = 'network_event',
  FILE_EVENT = 'file_event',
  PROCESS_EVENT = 'process_event',
  REGISTRY_EVENT = 'registry_event',
}

export enum EventSeverity {
  INFO = 'info',
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CRITICAL = 'critical',
}

@Entity('timeline_events')
export class TimelineEvent {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column()
  title: string;

  @Column('text', { nullable: true })
  description?: string;

  @Column({
    type: 'enum',
    enum: EventType,
  })
  type: EventType;

  @Column({
    type: 'enum',
    enum: EventSeverity,
    default: EventSeverity.INFO,
  })
  severity: EventSeverity;

  @Column()
  timestamp: Date;

  @Column({ nullable: true })
  source?: string;

  @Column({ nullable: true })
  sourceId?: string;

  @Column('simple-array', { default: '' })
  entities: string[];

  @Column('simple-array', { default: '' })
  iocs: string[];

  @Column('simple-array', { default: '' })
  attackTechniques: string[];

  @Column('jsonb', { nullable: true })
  rawData?: Record<string, any>;

  @Column('jsonb', { nullable: true })
  metadata?: Record<string, any>;

  @ManyToOne(() => Timeline, timeline => timeline.events)
  @JoinColumn({ name: 'timelineId' })
  timeline: Timeline;

  @Column()
  timelineId: string;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;
}
