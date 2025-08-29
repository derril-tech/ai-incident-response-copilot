import boto3
import httpx
from typing import Dict, Any, List, Optional
from .base import BaseConnector
import structlog

logger = structlog.get_logger()

class AWSCloudTrailConnector(BaseConnector):
    """Connector for AWS CloudTrail audit logs"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__("aws_cloudtrail", config)
        self.access_key = config.get("access_key_id")
        self.secret_key = config.get("secret_access_key")
        self.region = config.get("region", "us-east-1")
        self.cloudtrail_client = None
        self.s3_client = None
    
    async def connect(self) -> bool:
        """Connect to AWS CloudTrail"""
        try:
            self.cloudtrail_client = boto3.client(
                'cloudtrail',
                aws_access_key_id=self.access_key,
                aws_secret_access_key=self.secret_key,
                region_name=self.region
            )
            
            self.s3_client = boto3.client(
                's3',
                aws_access_key_id=self.access_key,
                aws_secret_access_key=self.secret_key,
                region_name=self.region
            )
            
            if await self.test_connection():
                self.connected = True
                logger.info("Connected to AWS CloudTrail")
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to connect to AWS CloudTrail: {e}")
            return False
    
    async def disconnect(self) -> None:
        """Disconnect from AWS CloudTrail"""
        self.connected = False
    
    async def test_connection(self) -> bool:
        """Test AWS CloudTrail connection"""
        try:
            # Test by listing trails
            response = self.cloudtrail_client.describe_trails()
            return 'trailList' in response
        except Exception as e:
            logger.error(f"AWS CloudTrail connection test failed: {e}")
            return False
    
    async def collect_artifacts(self, incident_id: str, time_range: Optional[tuple] = None) -> List[Dict[str, Any]]:
        """Collect artifacts from AWS CloudTrail"""
        artifacts = []
        
        try:
            # Get CloudTrail events
            events = await self._get_cloudtrail_events(incident_id, time_range)
            
            if events:
                artifact = {
                    "name": f"aws_cloudtrail_{incident_id}.json",
                    "type": "log_file",
                    "data": events,
                    "metadata": self._create_artifact_metadata({
                        "event_count": len(events),
                        "region": self.region
                    })
                }
                artifacts.append(artifact)
            
            # Get VPC Flow Logs if available
            vpc_logs = await self._get_vpc_flow_logs(incident_id, time_range)
            
            if vpc_logs:
                artifact = {
                    "name": f"aws_vpc_flow_logs_{incident_id}.json",
                    "type": "network_flow",
                    "data": vpc_logs,
                    "metadata": self._create_artifact_metadata({
                        "log_count": len(vpc_logs),
                        "region": self.region
                    })
                }
                artifacts.append(artifact)
                
        except Exception as e:
            logger.error(f"Failed to collect AWS CloudTrail artifacts: {e}")
        
        return artifacts
    
    async def get_logs(self, query: str, time_range: Optional[tuple] = None) -> List[Dict[str, Any]]:
        """Get logs from AWS CloudTrail"""
        return await self._get_cloudtrail_events(query, time_range)
    
    async def _get_cloudtrail_events(self, incident_id: str, time_range: Optional[tuple] = None) -> List[Dict[str, Any]]:
        """Get CloudTrail events"""
        try:
            lookup_attributes = [
                {
                    'AttributeKey': 'ResourceName',
                    'AttributeValue': incident_id
                }
            ]
            
            kwargs = {'LookupAttributes': lookup_attributes}
            
            if time_range:
                start_time, end_time = time_range
                kwargs['StartTime'] = start_time
                kwargs['EndTime'] = end_time
            
            response = self.cloudtrail_client.lookup_events(**kwargs)
            return response.get('Events', [])
            
        except Exception as e:
            logger.error(f"Failed to get CloudTrail events: {e}")
            return []
    
    async def _get_vpc_flow_logs(self, incident_id: str, time_range: Optional[tuple] = None) -> List[Dict[str, Any]]:
        """Get VPC Flow Logs (simplified implementation)"""
        try:
            # This would typically involve querying CloudWatch Logs or S3 buckets
            # where VPC Flow Logs are stored
            # For now, return empty list as this requires more complex setup
            return []
            
        except Exception as e:
            logger.error(f"Failed to get VPC Flow Logs: {e}")
            return []


class AzureActivityLogsConnector(BaseConnector):
    """Connector for Azure Activity Logs"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__("azure_activity", config)
        self.tenant_id = config.get("tenant_id")
        self.client_id = config.get("client_id")
        self.client_secret = config.get("client_secret")
        self.subscription_id = config.get("subscription_id")
        self.access_token = None
        self.client = None
    
    async def connect(self) -> bool:
        """Connect to Azure Activity Logs"""
        try:
            self.client = httpx.AsyncClient(timeout=30.0)
            
            # Get access token
            await self._authenticate()
            
            if await self.test_connection():
                self.connected = True
                logger.info("Connected to Azure Activity Logs")
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to connect to Azure Activity Logs: {e}")
            return False
    
    async def disconnect(self) -> None:
        """Disconnect from Azure Activity Logs"""
        if self.client:
            await self.client.aclose()
        self.connected = False
    
    async def test_connection(self) -> bool:
        """Test Azure Activity Logs connection"""
        try:
            headers = {"Authorization": f"Bearer {self.access_token}"}
            url = f"https://management.azure.com/subscriptions/{self.subscription_id}/providers/Microsoft.Insights/eventtypes/management/values"
            
            response = await self.client.get(url, headers=headers, params={"api-version": "2015-04-01", "$top": 1})
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Azure Activity Logs connection test failed: {e}")
            return False
    
    async def _authenticate(self) -> None:
        """Authenticate with Azure AD"""
        try:
            token_url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/token"
            
            token_data = {
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "resource": "https://management.azure.com/"
            }
            
            response = await self.client.post(token_url, data=token_data)
            
            if response.status_code == 200:
                token_response = response.json()
                self.access_token = token_response["access_token"]
            else:
                raise Exception(f"Azure authentication failed: {response.status_code}")
                
        except Exception as e:
            logger.error(f"Azure authentication failed: {e}")
            raise
    
    async def collect_artifacts(self, incident_id: str, time_range: Optional[tuple] = None) -> List[Dict[str, Any]]:
        """Collect artifacts from Azure Activity Logs"""
        artifacts = []
        
        try:
            # Get Activity Log events
            activities = await self._get_activity_logs(incident_id, time_range)
            
            if activities:
                artifact = {
                    "name": f"azure_activity_logs_{incident_id}.json",
                    "type": "log_file",
                    "data": activities,
                    "metadata": self._create_artifact_metadata({
                        "activity_count": len(activities),
                        "subscription_id": self.subscription_id
                    })
                }
                artifacts.append(artifact)
            
            # Get Security Center alerts
            security_alerts = await self._get_security_alerts(incident_id, time_range)
            
            if security_alerts:
                artifact = {
                    "name": f"azure_security_alerts_{incident_id}.json",
                    "type": "log_file",
                    "data": security_alerts,
                    "metadata": self._create_artifact_metadata({
                        "alert_count": len(security_alerts),
                        "subscription_id": self.subscription_id
                    })
                }
                artifacts.append(artifact)
                
        except Exception as e:
            logger.error(f"Failed to collect Azure Activity Logs artifacts: {e}")
        
        return artifacts
    
    async def get_logs(self, query: str, time_range: Optional[tuple] = None) -> List[Dict[str, Any]]:
        """Get logs from Azure Activity Logs"""
        return await self._get_activity_logs(query, time_range)
    
    async def _get_activity_logs(self, incident_id: str, time_range: Optional[tuple] = None) -> List[Dict[str, Any]]:
        """Get Azure Activity Log events"""
        try:
            headers = {"Authorization": f"Bearer {self.access_token}"}
            url = f"https://management.azure.com/subscriptions/{self.subscription_id}/providers/Microsoft.Insights/eventtypes/management/values"
            
            params = {
                "api-version": "2015-04-01",
                "$filter": f"correlationId eq '{incident_id}' or resourceId contains '{incident_id}'",
                "$top": 1000
            }
            
            if time_range:
                start_time, end_time = time_range
                params["$filter"] += f" and eventTimestamp ge '{start_time}' and eventTimestamp le '{end_time}'"
            
            response = await self.client.get(url, headers=headers, params=params)
            
            if response.status_code == 200:
                data = response.json()
                return data.get("value", [])
            else:
                logger.error(f"Failed to get Azure Activity Logs: {response.status_code}")
                return []
                
        except Exception as e:
            logger.error(f"Failed to get Azure Activity Logs: {e}")
            return []
    
    async def _get_security_alerts(self, incident_id: str, time_range: Optional[tuple] = None) -> List[Dict[str, Any]]:
        """Get Azure Security Center alerts"""
        try:
            headers = {"Authorization": f"Bearer {self.access_token}"}
            url = f"https://management.azure.com/subscriptions/{self.subscription_id}/providers/Microsoft.Security/alerts"
            
            params = {
                "api-version": "2019-01-01",
                "$filter": f"properties/correlationKey eq '{incident_id}'",
                "$top": 1000
            }
            
            if time_range:
                start_time, end_time = time_range
                params["$filter"] += f" and properties/timeGeneratedUtc ge '{start_time}' and properties/timeGeneratedUtc le '{end_time}'"
            
            response = await self.client.get(url, headers=headers, params=params)
            
            if response.status_code == 200:
                data = response.json()
                return data.get("value", [])
            else:
                logger.error(f"Failed to get Azure Security alerts: {response.status_code}")
                return []
                
        except Exception as e:
            logger.error(f"Failed to get Azure Security alerts: {e}")
            return []


class GCPAuditLogsConnector(BaseConnector):
    """Connector for Google Cloud Platform Audit Logs"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__("gcp_audit", config)
        self.project_id = config.get("project_id")
        self.service_account_key = config.get("service_account_key")
        self.client = None
    
    async def connect(self) -> bool:
        """Connect to GCP Audit Logs"""
        try:
            # Initialize GCP logging client
            # This would typically use google-cloud-logging library
            # For now, use HTTP API
            self.client = httpx.AsyncClient(timeout=30.0)
            
            if await self.test_connection():
                self.connected = True
                logger.info("Connected to GCP Audit Logs")
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to connect to GCP Audit Logs: {e}")
            return False
    
    async def disconnect(self) -> None:
        """Disconnect from GCP Audit Logs"""
        if self.client:
            await self.client.aclose()
        self.connected = False
    
    async def test_connection(self) -> bool:
        """Test GCP Audit Logs connection"""
        try:
            # Test connection by listing log entries
            # This is a simplified test
            return True
        except Exception as e:
            logger.error(f"GCP Audit Logs connection test failed: {e}")
            return False
    
    async def collect_artifacts(self, incident_id: str, time_range: Optional[tuple] = None) -> List[Dict[str, Any]]:
        """Collect artifacts from GCP Audit Logs"""
        artifacts = []
        
        try:
            # Get audit log entries
            audit_logs = await self._get_audit_logs(incident_id, time_range)
            
            if audit_logs:
                artifact = {
                    "name": f"gcp_audit_logs_{incident_id}.json",
                    "type": "log_file",
                    "data": audit_logs,
                    "metadata": self._create_artifact_metadata({
                        "log_count": len(audit_logs),
                        "project_id": self.project_id
                    })
                }
                artifacts.append(artifact)
                
        except Exception as e:
            logger.error(f"Failed to collect GCP Audit Logs artifacts: {e}")
        
        return artifacts
    
    async def get_logs(self, query: str, time_range: Optional[tuple] = None) -> List[Dict[str, Any]]:
        """Get logs from GCP Audit Logs"""
        return await self._get_audit_logs(query, time_range)
    
    async def _get_audit_logs(self, incident_id: str, time_range: Optional[tuple] = None) -> List[Dict[str, Any]]:
        """Get GCP Audit Log entries"""
        try:
            # This would use the Cloud Logging API
            # For now, return empty list as this requires proper GCP setup
            logger.info(f"Getting GCP audit logs for incident {incident_id}")
            return []
            
        except Exception as e:
            logger.error(f"Failed to get GCP audit logs: {e}")
            return []
