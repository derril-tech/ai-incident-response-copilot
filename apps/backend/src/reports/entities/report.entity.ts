import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn, UpdateDateColumn, ManyToOne, JoinColumn } from 'typeorm';
import { Incident } from '../../incidents/entities/incident.entity';

export enum ReportStatus {
  DRAFT = 'draft',
  REVIEW = 'review',
  APPROVED = 'approved',
  PUBLISHED = 'published',
}

export enum ReportType {
  INCIDENT_SUMMARY = 'incident_summary',
  FORENSIC_ANALYSIS = 'forensic_analysis',
  EXECUTIVE_SUMMARY = 'executive_summary',
  TECHNICAL_DETAILS = 'technical_details',
  LESSONS_LEARNED = 'lessons_learned',
}

@Entity('reports')
export class Report {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column()
  title: string;

  @Column({
    type: 'enum',
    enum: ReportType,
  })
  type: ReportType;

  @Column({
    type: 'enum',
    enum: ReportStatus,
    default: ReportStatus.DRAFT,
  })
  status: ReportStatus;

  @Column('text')
  content: string;

  @Column('text', { nullable: true })
  executiveSummary?: string;

  @Column('text', { nullable: true })
  findings?: string;

  @Column('text', { nullable: true })
  recommendations?: string;

  @Column('text', { nullable: true })
  lessonsLearned?: string;

  @Column({ nullable: true })
  authorId?: string;

  @Column({ nullable: true })
  reviewerId?: string;

  @Column({ nullable: true })
  approvedAt?: Date;

  @Column({ nullable: true })
  publishedAt?: Date;

  @Column('simple-array', { default: '' })
  tags: string[];

  @Column('jsonb', { nullable: true })
  metadata?: Record<string, any>;

  @ManyToOne(() => Incident, incident => incident.reports)
  @JoinColumn({ name: 'incidentId' })
  incident: Incident;

  @Column()
  incidentId: string;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;
}
