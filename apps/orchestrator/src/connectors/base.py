from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from datetime import datetime
import structlog

logger = structlog.get_logger()

class BaseConnector(ABC):
    """Base class for all external system connectors"""
    
    def __init__(self, name: str, config: Dict[str, Any]):
        self.name = name
        self.config = config
        self.connected = False
    
    @abstractmethod
    async def connect(self) -> bool:
        """Establish connection to external system"""
        pass
    
    @abstractmethod
    async def disconnect(self) -> None:
        """Close connection to external system"""
        pass
    
    @abstractmethod
    async def test_connection(self) -> bool:
        """Test if connection is working"""
        pass
    
    @abstractmethod
    async def collect_artifacts(self, incident_id: str, time_range: Optional[tuple] = None) -> List[Dict[str, Any]]:
        """Collect artifacts related to an incident"""
        pass
    
    @abstractmethod
    async def get_logs(self, query: str, time_range: Optional[tuple] = None) -> List[Dict[str, Any]]:
        """Query logs from the system"""
        pass
    
    def _create_artifact_metadata(self, source_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create standardized artifact metadata"""
        return {
            "source": self.name,
            "collected_at": datetime.utcnow().isoformat(),
            "source_data": source_data,
            "connector_version": "1.0.0"
        }
