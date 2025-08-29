import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ArtifactsService } from './artifacts.service';
import { ArtifactsController } from './artifacts.controller';
import { Artifact } from './entities/artifact.entity';

@Module({
  imports: [TypeOrmModule.forFeature([Artifact])],
  controllers: [ArtifactsController],
  providers: [ArtifactsService],
  exports: [ArtifactsService],
})
export class ArtifactsModule {}
