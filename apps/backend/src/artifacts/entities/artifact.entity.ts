import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn, UpdateDateColumn, ManyToOne, JoinColumn } from 'typeorm';
import { Incident } from '../../incidents/entities/incident.entity';

export enum ArtifactType {
  LOG_FILE = 'log_file',
  PCAP = 'pcap',
  MEMORY_DUMP = 'memory_dump',
  DISK_IMAGE = 'disk_image',
  NETWORK_FLOW = 'network_flow',
  EMAIL = 'email',
  DOCUMENT = 'document',
  EXECUTABLE = 'executable',
  REGISTRY_HIVE = 'registry_hive',
  EVENT_LOG = 'event_log',
}

export enum ArtifactStatus {
  PENDING = 'pending',
  PROCESSING = 'processing',
  ANALYZED = 'analyzed',
  QUARANTINED = 'quarantined',
  LEGAL_HOLD = 'legal_hold',
}

@Entity('artifacts')
export class Artifact {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column()
  name: string;

  @Column({
    type: 'enum',
    enum: ArtifactType,
  })
  type: ArtifactType;

  @Column({
    type: 'enum',
    enum: ArtifactStatus,
    default: ArtifactStatus.PENDING,
  })
  status: ArtifactStatus;

  @Column()
  sha256Hash: string;

  @Column({ nullable: true })
  md5Hash?: string;

  @Column({ type: 'bigint' })
  size: number;

  @Column()
  mimeType: string;

  @Column()
  storagePath: string;

  @Column({ nullable: true })
  source?: string;

  @Column({ nullable: true })
  collectedAt?: Date;

  @Column({ nullable: true })
  collectedBy?: string;

  @Column('jsonb', { nullable: true })
  chainOfCustody?: Record<string, any>[];

  @Column('jsonb', { nullable: true })
  metadata?: Record<string, any>;

  @Column({ default: false })
  isLegalHold: boolean;

  @Column({ default: false })
  isWormStorage: boolean;

  @ManyToOne(() => Incident, incident => incident.artifacts)
  @JoinColumn({ name: 'incidentId' })
  incident: Incident;

  @Column()
  incidentId: string;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;
}
