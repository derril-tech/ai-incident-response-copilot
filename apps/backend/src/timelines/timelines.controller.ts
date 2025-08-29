import { Controller, Get, Post, Body, Param, Query, UseGuards } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import { TimelinesService } from './timelines.service';

@ApiTags('Timelines')
@ApiBearerAuth()
@UseGuards(AuthGuard('jwt'))
@Controller('timelines')
export class TimelinesController {
  constructor(private readonly timelinesService: TimelinesService) {}

  @ApiOperation({ summary: 'Get all timelines' })
  @ApiResponse({ status: 200, description: 'List of timelines' })
  @Get()
  findAll(@Query('incidentId') incidentId?: string) {
    return this.timelinesService.findAll(incidentId);
  }

  @ApiOperation({ summary: 'Get timeline by ID' })
  @ApiResponse({ status: 200, description: 'Timeline details' })
  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.timelinesService.findOne(id);
  }

  @ApiOperation({ summary: 'Get timeline events' })
  @ApiResponse({ status: 200, description: 'Timeline events' })
  @Get(':id/events')
  getEvents(@Param('id') id: string) {
    return this.timelinesService.getEvents(id);
  }

  @ApiOperation({ summary: 'Add event to timeline' })
  @ApiResponse({ status: 201, description: 'Event added successfully' })
  @Post(':id/events')
  addEvent(@Param('id') id: string, @Body() eventData: any) {
    return this.timelinesService.addEvent(id, eventData);
  }
}
