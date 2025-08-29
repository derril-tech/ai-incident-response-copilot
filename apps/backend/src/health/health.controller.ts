import { Controller, Get } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';

@ApiTags('Health')
@Controller('health')
export class HealthController {
  @ApiOperation({ summary: 'Health check endpoint' })
  @ApiResponse({ status: 200, description: 'Service is healthy' })
  @Get()
  check() {
    return {
      status: 'ok',
      timestamp: new Date().toISOString(),
      service: 'ai-incident-response-backend',
      version: '1.0.0',
    };
  }

  @ApiOperation({ summary: 'Readiness check endpoint' })
  @ApiResponse({ status: 200, description: 'Service is ready' })
  @Get('ready')
  ready() {
    return {
      status: 'ready',
      timestamp: new Date().toISOString(),
    };
  }

  @ApiOperation({ summary: 'Liveness check endpoint' })
  @ApiResponse({ status: 200, description: 'Service is alive' })
  @Get('live')
  live() {
    return {
      status: 'alive',
      timestamp: new Date().toISOString(),
    };
  }
}
