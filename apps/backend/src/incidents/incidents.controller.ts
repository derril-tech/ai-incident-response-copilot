import { Controller, Get, Post, Body, Patch, Param, Delete, UseGuards } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import { IncidentsService } from './incidents.service';
import { CreateIncidentDto } from './dto/create-incident.dto';
import { UpdateIncidentDto } from './dto/update-incident.dto';

@ApiTags('Incidents')
@ApiBearerAuth()
@UseGuards(AuthGuard('jwt'))
@Controller('incidents')
export class IncidentsController {
  constructor(private readonly incidentsService: IncidentsService) {}

  @ApiOperation({ summary: 'Create a new incident' })
  @ApiResponse({ status: 201, description: 'Incident created successfully' })
  @Post()
  create(@Body() createIncidentDto: CreateIncidentDto) {
    return this.incidentsService.create(createIncidentDto);
  }

  @ApiOperation({ summary: 'Get all incidents' })
  @ApiResponse({ status: 200, description: 'List of incidents' })
  @Get()
  findAll() {
    return this.incidentsService.findAll();
  }

  @ApiOperation({ summary: 'Get incident by ID' })
  @ApiResponse({ status: 200, description: 'Incident details' })
  @ApiResponse({ status: 404, description: 'Incident not found' })
  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.incidentsService.findOne(id);
  }

  @ApiOperation({ summary: 'Update incident' })
  @ApiResponse({ status: 200, description: 'Incident updated successfully' })
  @ApiResponse({ status: 404, description: 'Incident not found' })
  @Patch(':id')
  update(@Param('id') id: string, @Body() updateIncidentDto: UpdateIncidentDto) {
    return this.incidentsService.update(id, updateIncidentDto);
  }

  @ApiOperation({ summary: 'Delete incident' })
  @ApiResponse({ status: 200, description: 'Incident deleted successfully' })
  @ApiResponse({ status: 404, description: 'Incident not found' })
  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.incidentsService.remove(id);
  }
}
