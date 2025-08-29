import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Report } from './entities/report.entity';

@Injectable()
export class ReportsService {
  constructor(
    @InjectRepository(Report)
    private reportRepository: Repository<Report>,
  ) {}

  async create(createReportDto: any): Promise<Report> {
    const report = this.reportRepository.create(createReportDto);
    return this.reportRepository.save(report);
  }

  async findAll(incidentId?: string): Promise<Report[]> {
    const query = this.reportRepository.createQueryBuilder('report');
    
    if (incidentId) {
      query.where('report.incidentId = :incidentId', { incidentId });
    }
    
    return query
      .orderBy('report.createdAt', 'DESC')
      .getMany();
  }

  async findOne(id: string): Promise<Report> {
    const report = await this.reportRepository.findOne({
      where: { id },
      relations: ['incident'],
    });

    if (!report) {
      throw new NotFoundException(`Report with ID ${id} not found`);
    }

    return report;
  }

  async update(id: string, updateReportDto: any): Promise<Report> {
    await this.reportRepository.update(id, updateReportDto);
    return this.findOne(id);
  }

  async remove(id: string): Promise<void> {
    const result = await this.reportRepository.delete(id);
    if (result.affected === 0) {
      throw new NotFoundException(`Report with ID ${id} not found`);
    }
  }
}
