import { IsString, IsOptional, IsEnum, IsArray, IsDateString, IsObject } from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IncidentStatus, IncidentSeverity } from '../entities/incident.entity';

export class CreateIncidentDto {
  @ApiProperty({ example: 'Suspicious network activity detected' })
  @IsString()
  title: string;

  @ApiPropertyOptional({ example: 'Multiple failed login attempts from external IP' })
  @IsOptional()
  @IsString()
  description?: string;

  @ApiPropertyOptional({ enum: IncidentSeverity, example: IncidentSeverity.HIGH })
  @IsOptional()
  @IsEnum(IncidentSeverity)
  severity?: IncidentSeverity;

  @ApiPropertyOptional({ example: 'user-uuid' })
  @IsOptional()
  @IsString()
  assigneeId?: string;

  @ApiPropertyOptional({ example: '2023-12-01T10:00:00Z' })
  @IsOptional()
  @IsDateString()
  detectedAt?: string;

  @ApiPropertyOptional({ example: ['malware', 'network', 'brute-force'] })
  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  tags?: string[];

  @ApiPropertyOptional({ example: { source: 'SIEM', alertId: 'ALT-123' } })
  @IsOptional()
  @IsObject()
  metadata?: Record<string, any>;
}
