import httpx
from typing import Dict, Any, List, Optional
from .base import BaseConnector
import structlog

logger = structlog.get_logger()

class CrowdStrikeConnector(BaseConnector):
    """Connector for CrowdStrike Falcon EDR"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__("crowdstrike", config)
        self.client_id = config.get("client_id")
        self.client_secret = config.get("client_secret")
        self.base_url = config.get("base_url", "https://api.crowdstrike.com")
        self.access_token = None
        self.client = None
    
    async def connect(self) -> bool:
        """Connect to CrowdStrike API"""
        try:
            self.client = httpx.AsyncClient(
                base_url=self.base_url,
                timeout=30.0
            )
            
            # Get access token
            await self._authenticate()
            
            if await self.test_connection():
                self.connected = True
                logger.info("Connected to CrowdStrike")
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to connect to CrowdStrike: {e}")
            return False
    
    async def disconnect(self) -> None:
        """Disconnect from CrowdStrike"""
        if self.client:
            await self.client.aclose()
        self.connected = False
    
    async def test_connection(self) -> bool:
        """Test CrowdStrike connection"""
        try:
            headers = {"Authorization": f"Bearer {self.access_token}"}
            response = await self.client.get("/devices/queries/devices/v1", headers=headers)
            return response.status_code == 200
        except Exception as e:
            logger.error(f"CrowdStrike connection test failed: {e}")
            return False
    
    async def _authenticate(self) -> None:
        """Authenticate with CrowdStrike API"""
        try:
            auth_data = {
                "client_id": self.client_id,
                "client_secret": self.client_secret
            }
            
            response = await self.client.post("/oauth2/token", data=auth_data)
            
            if response.status_code == 200:
                token_data = response.json()
                self.access_token = token_data["access_token"]
            else:
                raise Exception(f"Authentication failed: {response.status_code}")
                
        except Exception as e:
            logger.error(f"CrowdStrike authentication failed: {e}")
            raise
    
    async def collect_artifacts(self, incident_id: str, time_range: Optional[tuple] = None) -> List[Dict[str, Any]]:
        """Collect artifacts from CrowdStrike"""
        artifacts = []
        
        try:
            # Get detections related to incident
            detections = await self._get_detections(incident_id, time_range)
            
            if detections:
                artifact = {
                    "name": f"crowdstrike_detections_{incident_id}.json",
                    "type": "log_file",
                    "data": detections,
                    "metadata": self._create_artifact_metadata({
                        "detection_count": len(detections)
                    })
                }
                artifacts.append(artifact)
            
            # Get host information
            hosts = await self._get_hosts(incident_id, time_range)
            
            if hosts:
                artifact = {
                    "name": f"crowdstrike_hosts_{incident_id}.json",
                    "type": "log_file",
                    "data": hosts,
                    "metadata": self._create_artifact_metadata({
                        "host_count": len(hosts)
                    })
                }
                artifacts.append(artifact)
            
            # Get process information
            processes = await self._get_processes(incident_id, time_range)
            
            if processes:
                artifact = {
                    "name": f"crowdstrike_processes_{incident_id}.json",
                    "type": "log_file",
                    "data": processes,
                    "metadata": self._create_artifact_metadata({
                        "process_count": len(processes)
                    })
                }
                artifacts.append(artifact)
                
        except Exception as e:
            logger.error(f"Failed to collect CrowdStrike artifacts: {e}")
        
        return artifacts
    
    async def get_logs(self, query: str, time_range: Optional[tuple] = None) -> List[Dict[str, Any]]:
        """Get logs from CrowdStrike using FQL query"""
        try:
            headers = {"Authorization": f"Bearer {self.access_token}"}
            
            # Use Event Search API
            search_data = {"filter": query}
            if time_range:
                start_time, end_time = time_range
                search_data["filter"] += f" AND timestamp:>='{start_time}' AND timestamp:<='{end_time}'"
            
            response = await self.client.post(
                "/fwmgr/queries/events/v1",
                json=search_data,
                headers=headers
            )
            
            if response.status_code == 200:
                result = response.json()
                event_ids = result.get("resources", [])
                
                if event_ids:
                    return await self._get_event_details(event_ids)
                return []
            else:
                logger.error(f"Failed to query CrowdStrike events: {response.status_code}")
                return []
                
        except Exception as e:
            logger.error(f"CrowdStrike log query failed: {e}")
            return []
    
    async def _get_detections(self, incident_id: str, time_range: Optional[tuple] = None) -> List[Dict[str, Any]]:
        """Get detections from CrowdStrike"""
        try:
            headers = {"Authorization": f"Bearer {self.access_token}"}
            
            # Query detections
            filter_query = f"behaviors.incident_id:'{incident_id}'"
            if time_range:
                start_time, end_time = time_range
                filter_query += f" AND first_behavior:>='{start_time}' AND first_behavior:<='{end_time}'"
            
            params = {"filter": filter_query, "limit": 1000}
            
            response = await self.client.get("/detects/queries/detects/v1", headers=headers, params=params)
            
            if response.status_code == 200:
                detection_ids = response.json().get("resources", [])
                
                if detection_ids:
                    return await self._get_detection_details(detection_ids)
                return []
            else:
                logger.error(f"Failed to get CrowdStrike detections: {response.status_code}")
                return []
                
        except Exception as e:
            logger.error(f"Failed to get CrowdStrike detections: {e}")
            return []
    
    async def _get_detection_details(self, detection_ids: List[str]) -> List[Dict[str, Any]]:
        """Get detailed detection information"""
        try:
            headers = {"Authorization": f"Bearer {self.access_token}"}
            
            response = await self.client.post(
                "/detects/entities/summaries/GET/v1",
                json={"ids": detection_ids},
                headers=headers
            )
            
            if response.status_code == 200:
                return response.json().get("resources", [])
            else:
                logger.error(f"Failed to get detection details: {response.status_code}")
                return []
                
        except Exception as e:
            logger.error(f"Failed to get detection details: {e}")
            return []
    
    async def _get_hosts(self, incident_id: str, time_range: Optional[tuple] = None) -> List[Dict[str, Any]]:
        """Get host information from CrowdStrike"""
        try:
            headers = {"Authorization": f"Bearer {self.access_token}"}
            
            # Query hosts involved in incident
            filter_query = f"incident_id:'{incident_id}'"
            params = {"filter": filter_query, "limit": 1000}
            
            response = await self.client.get("/devices/queries/devices/v1", headers=headers, params=params)
            
            if response.status_code == 200:
                host_ids = response.json().get("resources", [])
                
                if host_ids:
                    return await self._get_host_details(host_ids)
                return []
            else:
                logger.error(f"Failed to get CrowdStrike hosts: {response.status_code}")
                return []
                
        except Exception as e:
            logger.error(f"Failed to get CrowdStrike hosts: {e}")
            return []
    
    async def _get_host_details(self, host_ids: List[str]) -> List[Dict[str, Any]]:
        """Get detailed host information"""
        try:
            headers = {"Authorization": f"Bearer {self.access_token}"}
            
            response = await self.client.post(
                "/devices/entities/devices/v1",
                json={"ids": host_ids},
                headers=headers
            )
            
            if response.status_code == 200:
                return response.json().get("resources", [])
            else:
                logger.error(f"Failed to get host details: {response.status_code}")
                return []
                
        except Exception as e:
            logger.error(f"Failed to get host details: {e}")
            return []
    
    async def _get_processes(self, incident_id: str, time_range: Optional[tuple] = None) -> List[Dict[str, Any]]:
        """Get process information from CrowdStrike"""
        try:
            headers = {"Authorization": f"Bearer {self.access_token}"}
            
            # Query processes related to incident
            filter_query = f"incident_id:'{incident_id}'"
            if time_range:
                start_time, end_time = time_range
                filter_query += f" AND timestamp:>='{start_time}' AND timestamp:<='{end_time}'"
            
            params = {"filter": filter_query, "limit": 1000}
            
            response = await self.client.get("/processes/queries/processes/v1", headers=headers, params=params)
            
            if response.status_code == 200:
                process_ids = response.json().get("resources", [])
                
                if process_ids:
                    return await self._get_process_details(process_ids)
                return []
            else:
                logger.error(f"Failed to get CrowdStrike processes: {response.status_code}")
                return []
                
        except Exception as e:
            logger.error(f"Failed to get CrowdStrike processes: {e}")
            return []
    
    async def _get_process_details(self, process_ids: List[str]) -> List[Dict[str, Any]]:
        """Get detailed process information"""
        try:
            headers = {"Authorization": f"Bearer {self.access_token}"}
            
            response = await self.client.post(
                "/processes/entities/processes/v1",
                json={"ids": process_ids},
                headers=headers
            )
            
            if response.status_code == 200:
                return response.json().get("resources", [])
            else:
                logger.error(f"Failed to get process details: {response.status_code}")
                return []
                
        except Exception as e:
            logger.error(f"Failed to get process details: {e}")
            return []
    
    async def _get_event_details(self, event_ids: List[str]) -> List[Dict[str, Any]]:
        """Get detailed event information"""
        try:
            headers = {"Authorization": f"Bearer {self.access_token}"}
            
            response = await self.client.post(
                "/fwmgr/entities/events/v1",
                json={"ids": event_ids},
                headers=headers
            )
            
            if response.status_code == 200:
                return response.json().get("resources", [])
            else:
                logger.error(f"Failed to get event details: {response.status_code}")
                return []
                
        except Exception as e:
            logger.error(f"Failed to get event details: {e}")
            return []


class SentinelOneConnector(BaseConnector):
    """Connector for SentinelOne EDR"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__("sentinelone", config)
        self.api_token = config.get("api_token")
        self.base_url = config.get("base_url")
        self.client = None
    
    async def connect(self) -> bool:
        """Connect to SentinelOne API"""
        try:
            self.client = httpx.AsyncClient(
                base_url=self.base_url,
                timeout=30.0,
                verify=self.config.get("verify_ssl", True)
            )
            
            if await self.test_connection():
                self.connected = True
                logger.info("Connected to SentinelOne")
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to connect to SentinelOne: {e}")
            return False
    
    async def disconnect(self) -> None:
        """Disconnect from SentinelOne"""
        if self.client:
            await self.client.aclose()
        self.connected = False
    
    async def test_connection(self) -> bool:
        """Test SentinelOne connection"""
        try:
            headers = {"Authorization": f"ApiToken {self.api_token}"}
            response = await self.client.get("/web/api/v2.1/system/status", headers=headers)
            return response.status_code == 200
        except Exception as e:
            logger.error(f"SentinelOne connection test failed: {e}")
            return False
    
    async def collect_artifacts(self, incident_id: str, time_range: Optional[tuple] = None) -> List[Dict[str, Any]]:
        """Collect artifacts from SentinelOne"""
        artifacts = []
        
        try:
            # Get threats related to incident
            threats = await self._get_threats(incident_id, time_range)
            
            if threats:
                artifact = {
                    "name": f"sentinelone_threats_{incident_id}.json",
                    "type": "log_file",
                    "data": threats,
                    "metadata": self._create_artifact_metadata({
                        "threat_count": len(threats)
                    })
                }
                artifacts.append(artifact)
            
            # Get agent information
            agents = await self._get_agents(incident_id, time_range)
            
            if agents:
                artifact = {
                    "name": f"sentinelone_agents_{incident_id}.json",
                    "type": "log_file",
                    "data": agents,
                    "metadata": self._create_artifact_metadata({
                        "agent_count": len(agents)
                    })
                }
                artifacts.append(artifact)
                
        except Exception as e:
            logger.error(f"Failed to collect SentinelOne artifacts: {e}")
        
        return artifacts
    
    async def get_logs(self, query: str, time_range: Optional[tuple] = None) -> List[Dict[str, Any]]:
        """Get logs from SentinelOne"""
        try:
            headers = {"Authorization": f"ApiToken {self.api_token}"}
            
            params = {"query": query, "limit": 1000}
            if time_range:
                start_time, end_time = time_range
                params["createdAt__gte"] = start_time
                params["createdAt__lte"] = end_time
            
            response = await self.client.get("/web/api/v2.1/activities", headers=headers, params=params)
            
            if response.status_code == 200:
                data = response.json()
                return data.get("data", [])
            else:
                logger.error(f"Failed to query SentinelOne activities: {response.status_code}")
                return []
                
        except Exception as e:
            logger.error(f"SentinelOne log query failed: {e}")
            return []
    
    async def _get_threats(self, incident_id: str, time_range: Optional[tuple] = None) -> List[Dict[str, Any]]:
        """Get threats from SentinelOne"""
        try:
            headers = {"Authorization": f"ApiToken {self.api_token}"}
            
            params = {"incidentId": incident_id, "limit": 1000}
            if time_range:
                start_time, end_time = time_range
                params["createdAt__gte"] = start_time
                params["createdAt__lte"] = end_time
            
            response = await self.client.get("/web/api/v2.1/threats", headers=headers, params=params)
            
            if response.status_code == 200:
                data = response.json()
                return data.get("data", [])
            else:
                logger.error(f"Failed to get SentinelOne threats: {response.status_code}")
                return []
                
        except Exception as e:
            logger.error(f"Failed to get SentinelOne threats: {e}")
            return []
    
    async def _get_agents(self, incident_id: str, time_range: Optional[tuple] = None) -> List[Dict[str, Any]]:
        """Get agents from SentinelOne"""
        try:
            headers = {"Authorization": f"ApiToken {self.api_token}"}
            
            params = {"incidentId": incident_id, "limit": 1000}
            
            response = await self.client.get("/web/api/v2.1/agents", headers=headers, params=params)
            
            if response.status_code == 200:
                data = response.json()
                return data.get("data", [])
            else:
                logger.error(f"Failed to get SentinelOne agents: {response.status_code}")
                return []
                
        except Exception as e:
            logger.error(f"Failed to get SentinelOne agents: {e}")
            return []
