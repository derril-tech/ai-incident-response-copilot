from typing import Dict, Any
import structlog
from .base import BaseWorker
from ..connectors.siem import SplunkConnector, QRadarConnector
from ..connectors.edr import CrowdStrikeConnector, SentinelOneConnector
from ..connectors.cloud import AWSCloudTrailConnector, AzureActivityLogsConnector, GCPAuditLogsConnector
from ..services.artifact_storage import ArtifactStorageService, ChainOfCustodyService

logger = structlog.get_logger()

class CollectorWorker(BaseWorker):
    """Worker for collecting incident artifacts"""
    
    def __init__(self):
        super().__init__("collector", ["incident.collect", "artifact.ingest"])
        self.storage_service = ArtifactStorageService()
        self.custody_service = ChainOfCustodyService()
        self.connectors = {}
    
    async def process_message(self, subject: str, data: Dict[str, Any]):
        """Process collection messages"""
        incident_id = data.get("incident_id")
        action = data.get("action")
        
        logger.info(f"Processing collection for incident {incident_id}", action=action)
        
        if action == "collect":
            await self._collect_artifacts(incident_id)
        elif action == "ingest":
            await self._ingest_artifact(data)
    
    async def _collect_artifacts(self, incident_id: str):
        """Collect artifacts for an incident"""
        logger.info(f"Collecting artifacts for incident {incident_id}")
        
        # Initialize connectors
        await self._initialize_connectors()
        
        collected_artifacts = []
        
        # Collect from each connected system
        for connector_name, connector in self.connectors.items():
            try:
                if connector.connected:
                    logger.info(f"Collecting from {connector_name}")
                    artifacts = await connector.collect_artifacts(incident_id)
                    
                    for artifact in artifacts:
                        # Store artifact with WORM compliance
                        stored_artifact = await self._store_artifact(
                            artifact, incident_id, connector_name
                        )
                        collected_artifacts.append(stored_artifact)
                        
                        # Add to chain of custody
                        await self.custody_service.add_custody_entry(
                            stored_artifact['artifact_id'],
                            'collected',
                            connector_name,
                            f"Artifact collected from {connector_name}"
                        )
                        
            except Exception as e:
                logger.error(f"Failed to collect from {connector_name}: {e}")
        
        logger.info(f"Collection completed for incident {incident_id}. Collected {len(collected_artifacts)} artifacts")
    
    async def _ingest_artifact(self, data: Dict[str, Any]):
        """Ingest a single artifact"""
        artifact_path = data.get("artifact_path")
        incident_id = data.get("incident_id")
        artifact_type = data.get("artifact_type", "unknown")
        
        logger.info(f"Ingesting artifact {artifact_path}")
        
        try:
            # Read artifact data (this would be from file system or network)
            # For now, simulate with empty data
            artifact_data = b"simulated artifact data"
            
            # Store with integrity verification
            stored_artifact = await self.storage_service.store_artifact(
                artifact_data=artifact_data,
                artifact_name=artifact_path.split('/')[-1],
                incident_id=incident_id,
                artifact_type=artifact_type,
                collected_by="manual_ingest"
            )
            
            # Add to chain of custody
            await self.custody_service.add_custody_entry(
                stored_artifact['storage_path'],
                'ingested',
                'manual_ingest',
                f"Artifact manually ingested from {artifact_path}"
            )
            
            logger.info(f"Successfully ingested artifact {artifact_path}")
            
        except Exception as e:
            logger.error(f"Failed to ingest artifact {artifact_path}: {e}")
    
    async def _simulate_collection(self, incident_id: str):
        """Simulate artifact collection for demo purposes"""
        import asyncio
        
        artifacts = [
            {"name": "system.log", "type": "log_file", "size": 1024000},
            {"name": "network.pcap", "type": "pcap", "size": 5120000},
            {"name": "memory.dmp", "type": "memory_dump", "size": 104857600},
        ]
        
        for artifact in artifacts:
            logger.info(f"Collecting {artifact['name']}")
            await asyncio.sleep(1)  # Simulate collection time
            
        logger.info(f"Collection completed for incident {incident_id}")
    
    async def _initialize_connectors(self):
        """Initialize available connectors"""
        # TODO: Load connector configurations from database or config
        connector_configs = {
            "splunk": {
                "base_url": "https://splunk.company.com:8089",
                "username": "admin",
                "password": "password",
                "token": None
            },
            "qradar": {
                "base_url": "https://qradar.company.com",
                "api_token": "your-api-token"
            },
            "crowdstrike": {
                "client_id": "your-client-id",
                "client_secret": "your-client-secret"
            },
            "aws_cloudtrail": {
                "access_key_id": "your-access-key",
                "secret_access_key": "your-secret-key",
                "region": "us-east-1"
            }
        }
        
        # Initialize connectors that are configured
        for name, config in connector_configs.items():
            try:
                if name == "splunk":
                    connector = SplunkConnector(config)
                elif name == "qradar":
                    connector = QRadarConnector(config)
                elif name == "crowdstrike":
                    connector = CrowdStrikeConnector(config)
                elif name == "aws_cloudtrail":
                    connector = AWSCloudTrailConnector(config)
                else:
                    continue
                
                # Test connection
                if await connector.connect():
                    self.connectors[name] = connector
                    logger.info(f"Initialized connector: {name}")
                else:
                    logger.warning(f"Failed to connect to {name}")
                    
            except Exception as e:
                logger.error(f"Failed to initialize {name} connector: {e}")
    
    async def _store_artifact(self, artifact: Dict[str, Any], incident_id: str, source: str) -> Dict[str, Any]:
        """Store artifact using storage service"""
        try:
            # Convert artifact data to bytes
            if isinstance(artifact.get('data'), (dict, list)):
                import json
                artifact_data = json.dumps(artifact['data']).encode('utf-8')
            else:
                artifact_data = str(artifact.get('data', '')).encode('utf-8')
            
            # Store artifact
            stored_artifact = await self.storage_service.store_artifact(
                artifact_data=artifact_data,
                artifact_name=artifact['name'],
                incident_id=incident_id,
                artifact_type=artifact['type'],
                metadata=artifact.get('metadata', {}),
                collected_by=source
            )
            
            # Add artifact ID for tracking
            stored_artifact['artifact_id'] = stored_artifact['storage_path']
            
            return stored_artifact
            
        except Exception as e:
            logger.error(f"Failed to store artifact {artifact['name']}: {e}")
            raise
