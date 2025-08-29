import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { TimelinesService } from './timelines.service';
import { TimelinesController } from './timelines.controller';
import { Timeline } from './entities/timeline.entity';
import { TimelineEvent } from './entities/timeline-event.entity';

@Module({
  imports: [TypeOrmModule.forFeature([Timeline, TimelineEvent])],
  controllers: [TimelinesController],
  providers: [TimelinesService],
  exports: [TimelinesService],
})
export class TimelinesModule {}
