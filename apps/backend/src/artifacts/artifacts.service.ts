import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Artifact } from './entities/artifact.entity';
import { CreateArtifactDto } from './dto/create-artifact.dto';
import { UpdateArtifactDto } from './dto/update-artifact.dto';
import * as crypto from 'crypto';

@Injectable()
export class ArtifactsService {
  constructor(
    @InjectRepository(Artifact)
    private artifactRepository: Repository<Artifact>,
  ) {}

  async create(createArtifactDto: CreateArtifactDto): Promise<Artifact> {
    const artifact = this.artifactRepository.create(createArtifactDto);
    
    // Initialize chain of custody
    artifact.chainOfCustody = [{
      action: 'created',
      timestamp: new Date(),
      user: createArtifactDto.collectedBy || 'system',
      details: 'Artifact created in system',
    }];

    return this.artifactRepository.save(artifact);
  }

  async findAll(incidentId?: string): Promise<Artifact[]> {
    const query = this.artifactRepository.createQueryBuilder('artifact');
    
    if (incidentId) {
      query.where('artifact.incidentId = :incidentId', { incidentId });
    }
    
    return query
      .orderBy('artifact.createdAt', 'DESC')
      .getMany();
  }

  async findOne(id: string): Promise<Artifact> {
    const artifact = await this.artifactRepository.findOne({
      where: { id },
      relations: ['incident'],
    });

    if (!artifact) {
      throw new NotFoundException(`Artifact with ID ${id} not found`);
    }

    return artifact;
  }

  async update(id: string, updateArtifactDto: UpdateArtifactDto): Promise<Artifact> {
    const artifact = await this.findOne(id);
    
    // Add to chain of custody
    const custodyEntry = {
      action: 'updated',
      timestamp: new Date(),
      user: updateArtifactDto.updatedBy || 'system',
      details: `Updated: ${Object.keys(updateArtifactDto).join(', ')}`,
    };
    
    artifact.chainOfCustody = [...(artifact.chainOfCustody || []), custodyEntry];
    
    Object.assign(artifact, updateArtifactDto);
    return this.artifactRepository.save(artifact);
  }

  async remove(id: string): Promise<void> {
    const result = await this.artifactRepository.delete(id);
    if (result.affected === 0) {
      throw new NotFoundException(`Artifact with ID ${id} not found`);
    }
  }

  async calculateHash(buffer: Buffer): Promise<{ sha256: string; md5: string }> {
    const sha256 = crypto.createHash('sha256').update(buffer).digest('hex');
    const md5 = crypto.createHash('md5').update(buffer).digest('hex');
    return { sha256, md5 };
  }

  async setLegalHold(id: string, isLegalHold: boolean, updatedBy: string): Promise<Artifact> {
    const artifact = await this.findOne(id);
    
    const custodyEntry = {
      action: isLegalHold ? 'legal_hold_enabled' : 'legal_hold_disabled',
      timestamp: new Date(),
      user: updatedBy,
      details: `Legal hold ${isLegalHold ? 'enabled' : 'disabled'}`,
    };
    
    artifact.chainOfCustody = [...(artifact.chainOfCustody || []), custodyEntry];
    artifact.isLegalHold = isLegalHold;
    
    return this.artifactRepository.save(artifact);
  }
}
