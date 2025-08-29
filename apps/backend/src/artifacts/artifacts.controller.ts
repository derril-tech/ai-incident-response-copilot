import { Controller, Get, Post, Body, Patch, Param, Delete, Query, UseGuards } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth, ApiQuery } from '@nestjs/swagger';
import { ArtifactsService } from './artifacts.service';
import { CreateArtifactDto } from './dto/create-artifact.dto';
import { UpdateArtifactDto } from './dto/update-artifact.dto';

@ApiTags('Artifacts')
@ApiBearerAuth()
@UseGuards(AuthGuard('jwt'))
@Controller('artifacts')
export class ArtifactsController {
  constructor(private readonly artifactsService: ArtifactsService) {}

  @ApiOperation({ summary: 'Create a new artifact' })
  @ApiResponse({ status: 201, description: 'Artifact created successfully' })
  @Post()
  create(@Body() createArtifactDto: CreateArtifactDto) {
    return this.artifactsService.create(createArtifactDto);
  }

  @ApiOperation({ summary: 'Get all artifacts' })
  @ApiResponse({ status: 200, description: 'List of artifacts' })
  @ApiQuery({ name: 'incidentId', required: false, description: 'Filter by incident ID' })
  @Get()
  findAll(@Query('incidentId') incidentId?: string) {
    return this.artifactsService.findAll(incidentId);
  }

  @ApiOperation({ summary: 'Get artifact by ID' })
  @ApiResponse({ status: 200, description: 'Artifact details' })
  @ApiResponse({ status: 404, description: 'Artifact not found' })
  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.artifactsService.findOne(id);
  }

  @ApiOperation({ summary: 'Update artifact' })
  @ApiResponse({ status: 200, description: 'Artifact updated successfully' })
  @ApiResponse({ status: 404, description: 'Artifact not found' })
  @Patch(':id')
  update(@Param('id') id: string, @Body() updateArtifactDto: UpdateArtifactDto) {
    return this.artifactsService.update(id, updateArtifactDto);
  }

  @ApiOperation({ summary: 'Set legal hold on artifact' })
  @ApiResponse({ status: 200, description: 'Legal hold updated successfully' })
  @Patch(':id/legal-hold')
  setLegalHold(
    @Param('id') id: string,
    @Body() body: { isLegalHold: boolean; updatedBy: string }
  ) {
    return this.artifactsService.setLegalHold(id, body.isLegalHold, body.updatedBy);
  }

  @ApiOperation({ summary: 'Delete artifact' })
  @ApiResponse({ status: 200, description: 'Artifact deleted successfully' })
  @ApiResponse({ status: 404, description: 'Artifact not found' })
  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.artifactsService.remove(id);
  }
}
