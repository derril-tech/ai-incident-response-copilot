import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Timeline } from './entities/timeline.entity';
import { TimelineEvent } from './entities/timeline-event.entity';

@Injectable()
export class TimelinesService {
  constructor(
    @InjectRepository(Timeline)
    private timelineRepository: Repository<Timeline>,
    @InjectRepository(TimelineEvent)
    private eventRepository: Repository<TimelineEvent>,
  ) {}

  async create(createTimelineDto: any): Promise<Timeline> {
    const timeline = this.timelineRepository.create(createTimelineDto);
    return this.timelineRepository.save(timeline);
  }

  async findAll(incidentId?: string): Promise<Timeline[]> {
    const query = this.timelineRepository.createQueryBuilder('timeline')
      .leftJoinAndSelect('timeline.events', 'events')
      .orderBy('timeline.createdAt', 'DESC')
      .addOrderBy('events.timestamp', 'ASC');
    
    if (incidentId) {
      query.where('timeline.incidentId = :incidentId', { incidentId });
    }
    
    return query.getMany();
  }

  async findOne(id: string): Promise<Timeline> {
    const timeline = await this.timelineRepository.findOne({
      where: { id },
      relations: ['incident', 'events'],
    });

    if (!timeline) {
      throw new NotFoundException(`Timeline with ID ${id} not found`);
    }

    return timeline;
  }

  async addEvent(timelineId: string, eventData: any): Promise<TimelineEvent> {
    const timeline = await this.findOne(timelineId);
    
    const event = this.eventRepository.create({
      ...eventData,
      timelineId: timeline.id,
    });
    
    return this.eventRepository.save(event);
  }

  async getEvents(timelineId: string): Promise<TimelineEvent[]> {
    return this.eventRepository.find({
      where: { timelineId },
      order: { timestamp: 'ASC' },
    });
  }
}
