import { PartialType } from '@nestjs/swagger';
import { IsOptional, IsEnum } from 'class-validator';
import { CreateIncidentDto } from './create-incident.dto';
import { IncidentStatus } from '../entities/incident.entity';

export class UpdateIncidentDto extends PartialType(CreateIncidentDto) {
  @IsOptional()
  @IsEnum(IncidentStatus)
  status?: IncidentStatus;
}
