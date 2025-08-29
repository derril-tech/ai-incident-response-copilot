import { Controller, Get, Post, Body, Patch, Param, Delete, Query, UseGuards } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import { ReportsService } from './reports.service';

@ApiTags('Reports')
@ApiBearerAuth()
@UseGuards(AuthGuard('jwt'))
@Controller('reports')
export class ReportsController {
  constructor(private readonly reportsService: ReportsService) {}

  @ApiOperation({ summary: 'Create a new report' })
  @ApiResponse({ status: 201, description: 'Report created successfully' })
  @Post()
  create(@Body() createReportDto: any) {
    return this.reportsService.create(createReportDto);
  }

  @ApiOperation({ summary: 'Get all reports' })
  @ApiResponse({ status: 200, description: 'List of reports' })
  @Get()
  findAll(@Query('incidentId') incidentId?: string) {
    return this.reportsService.findAll(incidentId);
  }

  @ApiOperation({ summary: 'Get report by ID' })
  @ApiResponse({ status: 200, description: 'Report details' })
  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.reportsService.findOne(id);
  }

  @ApiOperation({ summary: 'Update report' })
  @ApiResponse({ status: 200, description: 'Report updated successfully' })
  @Patch(':id')
  update(@Param('id') id: string, @Body() updateReportDto: any) {
    return this.reportsService.update(id, updateReportDto);
  }

  @ApiOperation({ summary: 'Delete report' })
  @ApiResponse({ status: 200, description: 'Report deleted successfully' })
  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.reportsService.remove(id);
  }
}
