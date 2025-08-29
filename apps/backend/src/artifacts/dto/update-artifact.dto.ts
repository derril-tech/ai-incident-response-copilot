import { PartialType } from '@nestjs/swagger';
import { IsOptional, IsEnum, IsString } from 'class-validator';
import { CreateArtifactDto } from './create-artifact.dto';
import { ArtifactStatus } from '../entities/artifact.entity';

export class UpdateArtifactDto extends PartialType(CreateArtifactDto) {
  @IsOptional()
  @IsEnum(ArtifactStatus)
  status?: ArtifactStatus;

  @IsOptional()
  @IsString()
  updatedBy?: string;
}
