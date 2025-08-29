import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Incident } from './entities/incident.entity';
import { CreateIncidentDto } from './dto/create-incident.dto';
import { UpdateIncidentDto } from './dto/update-incident.dto';

@Injectable()
export class IncidentsService {
  constructor(
    @InjectRepository(Incident)
    private incidentRepository: Repository<Incident>,
  ) {}

  async create(createIncidentDto: CreateIncidentDto): Promise<Incident> {
    const incident = this.incidentRepository.create(createIncidentDto);
    return this.incidentRepository.save(incident);
  }

  async findAll(): Promise<Incident[]> {
    return this.incidentRepository.find({
      relations: ['artifacts', 'timelines', 'reports'],
      order: { createdAt: 'DESC' },
    });
  }

  async findOne(id: string): Promise<Incident> {
    const incident = await this.incidentRepository.findOne({
      where: { id },
      relations: ['artifacts', 'timelines', 'reports'],
    });

    if (!incident) {
      throw new NotFoundException(`Incident with ID ${id} not found`);
    }

    return incident;
  }

  async update(id: string, updateIncidentDto: UpdateIncidentDto): Promise<Incident> {
    await this.incidentRepository.update(id, updateIncidentDto);
    return this.findOne(id);
  }

  async remove(id: string): Promise<void> {
    const result = await this.incidentRepository.delete(id);
    if (result.affected === 0) {
      throw new NotFoundException(`Incident with ID ${id} not found`);
    }
  }
}
