import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn, UpdateDateColumn, ManyToOne, JoinColumn, OneToMany } from 'typeorm';
import { Incident } from '../../incidents/entities/incident.entity';
import { TimelineEvent } from './timeline-event.entity';

@Entity('timelines')
export class Timeline {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column()
  name: string;

  @Column('text', { nullable: true })
  description?: string;

  @Column({ nullable: true })
  startTime?: Date;

  @Column({ nullable: true })
  endTime?: Date;

  @Column('jsonb', { nullable: true })
  metadata?: Record<string, any>;

  @ManyToOne(() => Incident, incident => incident.timelines)
  @JoinColumn({ name: 'incidentId' })
  incident: Incident;

  @Column()
  incidentId: string;

  @OneToMany(() => TimelineEvent, event => event.timeline)
  events: TimelineEvent[];

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;
}
