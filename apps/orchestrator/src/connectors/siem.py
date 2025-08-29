import httpx
from typing import Dict, Any, List, Optional
from .base import BaseConnector
import structlog

logger = structlog.get_logger()

class SplunkConnector(BaseConnector):
    """Connector for Splunk SIEM"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__("splunk", config)
        self.base_url = config.get("base_url")
        self.username = config.get("username")
        self.password = config.get("password")
        self.token = config.get("token")
        self.client = None
    
    async def connect(self) -> bool:
        """Connect to Splunk"""
        try:
            self.client = httpx.AsyncClient(
                base_url=self.base_url,
                timeout=30.0,
                verify=self.config.get("verify_ssl", True)
            )
            
            # Test authentication
            if await self.test_connection():
                self.connected = True
                logger.info("Connected to Splunk")
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to connect to Splunk: {e}")
            return False
    
    async def disconnect(self) -> None:
        """Disconnect from Splunk"""
        if self.client:
            await self.client.aclose()
        self.connected = False
    
    async def test_connection(self) -> bool:
        """Test Splunk connection"""
        try:
            headers = {"Authorization": f"Bearer {self.token}"} if self.token else None
            auth = (self.username, self.password) if not self.token else None
            
            response = await self.client.get("/services/server/info", headers=headers, auth=auth)
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Splunk connection test failed: {e}")
            return False
    
    async def collect_artifacts(self, incident_id: str, time_range: Optional[tuple] = None) -> List[Dict[str, Any]]:
        """Collect artifacts from Splunk"""
        artifacts = []
        
        # Define search queries for different artifact types
        queries = [
            {
                "name": "security_alerts",
                "search": f'search index=security incident_id="{incident_id}" OR tag="{incident_id}"',
                "artifact_type": "log_file"
            },
            {
                "name": "network_logs", 
                "search": f'search index=network incident_id="{incident_id}"',
                "artifact_type": "network_flow"
            },
            {
                "name": "system_logs",
                "search": f'search index=main incident_id="{incident_id}"',
                "artifact_type": "log_file"
            }
        ]
        
        for query_config in queries:
            try:
                results = await self._execute_search(query_config["search"], time_range)
                
                if results:
                    artifact = {
                        "name": f"{query_config['name']}_{incident_id}.json",
                        "type": query_config["artifact_type"],
                        "data": results,
                        "metadata": self._create_artifact_metadata({
                            "query": query_config["search"],
                            "result_count": len(results)
                        })
                    }
                    artifacts.append(artifact)
                    
            except Exception as e:
                logger.error(f"Failed to collect {query_config['name']}: {e}")
        
        return artifacts
    
    async def get_logs(self, query: str, time_range: Optional[tuple] = None) -> List[Dict[str, Any]]:
        """Execute Splunk search query"""
        return await self._execute_search(query, time_range)
    
    async def _execute_search(self, search_query: str, time_range: Optional[tuple] = None) -> List[Dict[str, Any]]:
        """Execute search in Splunk"""
        try:
            # Add time range to query if provided
            if time_range:
                start_time, end_time = time_range
                search_query += f' earliest="{start_time}" latest="{end_time}"'
            
            # Create search job
            headers = {"Authorization": f"Bearer {self.token}"} if self.token else None
            auth = (self.username, self.password) if not self.token else None
            
            search_data = {
                "search": search_query,
                "output_mode": "json",
                "count": 10000  # Limit results
            }
            
            response = await self.client.post(
                "/services/search/jobs",
                data=search_data,
                headers=headers,
                auth=auth
            )
            
            if response.status_code == 201:
                # Parse job ID and wait for completion
                job_id = response.text.strip()
                return await self._get_search_results(job_id, headers, auth)
            else:
                logger.error(f"Failed to create Splunk search job: {response.status_code}")
                return []
                
        except Exception as e:
            logger.error(f"Splunk search execution failed: {e}")
            return []
    
    async def _get_search_results(self, job_id: str, headers: dict, auth: tuple) -> List[Dict[str, Any]]:
        """Get results from completed search job"""
        import asyncio
        
        # Wait for job completion (simplified)
        await asyncio.sleep(5)
        
        try:
            response = await self.client.get(
                f"/services/search/jobs/{job_id}/results",
                params={"output_mode": "json"},
                headers=headers,
                auth=auth
            )
            
            if response.status_code == 200:
                data = response.json()
                return data.get("results", [])
            else:
                logger.error(f"Failed to get search results: {response.status_code}")
                return []
                
        except Exception as e:
            logger.error(f"Failed to retrieve search results: {e}")
            return []


class QRadarConnector(BaseConnector):
    """Connector for IBM QRadar SIEM"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__("qradar", config)
        self.base_url = config.get("base_url")
        self.api_token = config.get("api_token")
        self.client = None
    
    async def connect(self) -> bool:
        """Connect to QRadar"""
        try:
            self.client = httpx.AsyncClient(
                base_url=self.base_url,
                timeout=30.0,
                verify=self.config.get("verify_ssl", True)
            )
            
            if await self.test_connection():
                self.connected = True
                logger.info("Connected to QRadar")
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to connect to QRadar: {e}")
            return False
    
    async def disconnect(self) -> None:
        """Disconnect from QRadar"""
        if self.client:
            await self.client.aclose()
        self.connected = False
    
    async def test_connection(self) -> bool:
        """Test QRadar connection"""
        try:
            headers = {"SEC": self.api_token, "Version": "12.0"}
            response = await self.client.get("/api/system/about", headers=headers)
            return response.status_code == 200
        except Exception as e:
            logger.error(f"QRadar connection test failed: {e}")
            return False
    
    async def collect_artifacts(self, incident_id: str, time_range: Optional[tuple] = None) -> List[Dict[str, Any]]:
        """Collect artifacts from QRadar"""
        artifacts = []
        
        try:
            # Get offenses related to incident
            offenses = await self._get_offenses(incident_id, time_range)
            
            if offenses:
                artifact = {
                    "name": f"qradar_offenses_{incident_id}.json",
                    "type": "log_file",
                    "data": offenses,
                    "metadata": self._create_artifact_metadata({
                        "offense_count": len(offenses)
                    })
                }
                artifacts.append(artifact)
            
            # Get events related to incident
            events = await self._get_events(incident_id, time_range)
            
            if events:
                artifact = {
                    "name": f"qradar_events_{incident_id}.json",
                    "type": "log_file", 
                    "data": events,
                    "metadata": self._create_artifact_metadata({
                        "event_count": len(events)
                    })
                }
                artifacts.append(artifact)
                
        except Exception as e:
            logger.error(f"Failed to collect QRadar artifacts: {e}")
        
        return artifacts
    
    async def get_logs(self, query: str, time_range: Optional[tuple] = None) -> List[Dict[str, Any]]:
        """Get logs from QRadar using AQL query"""
        try:
            headers = {"SEC": self.api_token, "Version": "12.0", "Content-Type": "application/json"}
            
            search_data = {"query_expression": query}
            if time_range:
                start_time, end_time = time_range
                search_data["query_expression"] += f" LAST {end_time - start_time} MINUTES"
            
            response = await self.client.post(
                "/api/ariel/searches",
                json=search_data,
                headers=headers
            )
            
            if response.status_code == 201:
                search_id = response.json()["search_id"]
                return await self._get_search_results(search_id)
            else:
                logger.error(f"Failed to create QRadar search: {response.status_code}")
                return []
                
        except Exception as e:
            logger.error(f"QRadar log query failed: {e}")
            return []
    
    async def _get_offenses(self, incident_id: str, time_range: Optional[tuple] = None) -> List[Dict[str, Any]]:
        """Get offenses from QRadar"""
        try:
            headers = {"SEC": self.api_token, "Version": "12.0"}
            params = {"filter": f"description ILIKE '%{incident_id}%'"}
            
            response = await self.client.get("/api/siem/offenses", headers=headers, params=params)
            
            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"Failed to get QRadar offenses: {response.status_code}")
                return []
                
        except Exception as e:
            logger.error(f"Failed to get QRadar offenses: {e}")
            return []
    
    async def _get_events(self, incident_id: str, time_range: Optional[tuple] = None) -> List[Dict[str, Any]]:
        """Get events from QRadar"""
        # Implement AQL query for events
        aql_query = f"SELECT * FROM events WHERE description ILIKE '%{incident_id}%' LIMIT 1000"
        return await self.get_logs(aql_query, time_range)
    
    async def _get_search_results(self, search_id: str) -> List[Dict[str, Any]]:
        """Get results from QRadar search"""
        import asyncio
        
        # Wait for search completion
        await asyncio.sleep(10)
        
        try:
            headers = {"SEC": self.api_token, "Version": "12.0"}
            response = await self.client.get(f"/api/ariel/searches/{search_id}/results", headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                return data.get("events", [])
            else:
                logger.error(f"Failed to get QRadar search results: {response.status_code}")
                return []
                
        except Exception as e:
            logger.error(f"Failed to retrieve QRadar search results: {e}")
            return []
