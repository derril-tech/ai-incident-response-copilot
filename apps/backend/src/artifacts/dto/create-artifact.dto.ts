import { IsString, IsEnum, IsOptional, IsNumber, IsBoolean, IsObject, IsDateString } from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { ArtifactType } from '../entities/artifact.entity';

export class CreateArtifactDto {
  @ApiProperty({ example: 'suspicious_file.exe' })
  @IsString()
  name: string;

  @ApiProperty({ enum: ArtifactType, example: ArtifactType.EXECUTABLE })
  @IsEnum(ArtifactType)
  type: ArtifactType;

  @ApiProperty({ example: 'a1b2c3d4e5f6...' })
  @IsString()
  sha256Hash: string;

  @ApiPropertyOptional({ example: 'f1e2d3c4b5a6...' })
  @IsOptional()
  @IsString()
  md5Hash?: string;

  @ApiProperty({ example: 1048576 })
  @IsNumber()
  size: number;

  @ApiProperty({ example: 'application/octet-stream' })
  @IsString()
  mimeType: string;

  @ApiProperty({ example: '/storage/artifacts/2023/12/suspicious_file.exe' })
  @IsString()
  storagePath: string;

  @ApiProperty({ example: 'incident-uuid' })
  @IsString()
  incidentId: string;

  @ApiPropertyOptional({ example: 'EDR System' })
  @IsOptional()
  @IsString()
  source?: string;

  @ApiPropertyOptional({ example: '2023-12-01T10:00:00Z' })
  @IsOptional()
  @IsDateString()
  collectedAt?: string;

  @ApiPropertyOptional({ example: 'analyst@company.com' })
  @IsOptional()
  @IsString()
  collectedBy?: string;

  @ApiPropertyOptional({ example: { hostname: 'server01', path: '/tmp/malware' } })
  @IsOptional()
  @IsObject()
  metadata?: Record<string, any>;

  @ApiPropertyOptional({ example: false })
  @IsOptional()
  @IsBoolean()
  isLegalHold?: boolean;

  @ApiPropertyOptional({ example: true })
  @IsOptional()
  @IsBoolean()
  isWormStorage?: boolean;
}
