import hashlib
import boto3
from datetime import datetime
from typing import Dict, Any, Optional, BinaryIO
import structlog
from ..core.config import settings

logger = structlog.get_logger()

class ArtifactStorageService:
    """Service for storing artifacts with WORM compliance and chain of custody"""
    
    def __init__(self):
        self.s3_client = boto3.client(
            's3',
            endpoint_url=settings.S3_ENDPOINT,
            aws_access_key_id=settings.S3_ACCESS_KEY,
            aws_secret_access_key=settings.S3_SECRET_KEY
        )
        self.bucket_name = settings.S3_BUCKET
    
    async def store_artifact(
        self,
        artifact_data: bytes,
        artifact_name: str,
        incident_id: str,
        artifact_type: str,
        metadata: Optional[Dict[str, Any]] = None,
        collected_by: str = "system"
    ) -> Dict[str, Any]:
        """Store artifact with integrity hashing and chain of custody"""
        
        try:
            # Calculate hashes
            hashes = self._calculate_hashes(artifact_data)
            
            # Generate storage path
            storage_path = self._generate_storage_path(incident_id, artifact_name, hashes['sha256'])
            
            # Create chain of custody entry
            custody_entry = {
                "action": "stored",
                "timestamp": datetime.utcnow().isoformat(),
                "user": collected_by,
                "details": f"Artifact stored in WORM storage at {storage_path}",
                "integrity_hash": hashes['sha256']
            }
            
            # Prepare metadata
            storage_metadata = {
                "incident_id": incident_id,
                "artifact_type": artifact_type,
                "sha256_hash": hashes['sha256'],
                "md5_hash": hashes['md5'],
                "size": str(len(artifact_data)),
                "collected_by": collected_by,
                "stored_at": datetime.utcnow().isoformat(),
                "chain_of_custody": str([custody_entry]),
                "worm_enabled": "true"
            }
            
            if metadata:
                storage_metadata.update({f"custom_{k}": str(v) for k, v in metadata.items()})
            
            # Store in S3 with WORM settings
            self.s3_client.put_object(
                Bucket=self.bucket_name,
                Key=storage_path,
                Body=artifact_data,
                Metadata=storage_metadata,
                ServerSideEncryption='AES256',
                StorageClass='STANDARD_IA',  # For long-term retention
                ObjectLockMode='COMPLIANCE',  # WORM compliance
                ObjectLockRetainUntilDate=datetime(2030, 1, 1)  # Retention period
            )
            
            logger.info(f"Stored artifact {artifact_name} for incident {incident_id}")
            
            return {
                "storage_path": storage_path,
                "sha256_hash": hashes['sha256'],
                "md5_hash": hashes['md5'],
                "size": len(artifact_data),
                "chain_of_custody": [custody_entry],
                "worm_enabled": True,
                "stored_at": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Failed to store artifact {artifact_name}: {e}")
            raise
    
    async def retrieve_artifact(self, storage_path: str) -> Dict[str, Any]:
        """Retrieve artifact and verify integrity"""
        
        try:
            # Get object from S3
            response = self.s3_client.get_object(
                Bucket=self.bucket_name,
                Key=storage_path
            )
            
            artifact_data = response['Body'].read()
            metadata = response.get('Metadata', {})
            
            # Verify integrity
            current_hashes = self._calculate_hashes(artifact_data)
            stored_sha256 = metadata.get('sha256_hash')
            
            if stored_sha256 and current_hashes['sha256'] != stored_sha256:
                logger.error(f"Integrity check failed for artifact {storage_path}")
                raise Exception("Artifact integrity verification failed")
            
            # Add retrieval to chain of custody
            custody_entry = {
                "action": "retrieved",
                "timestamp": datetime.utcnow().isoformat(),
                "user": "system",
                "details": f"Artifact retrieved from {storage_path}",
                "integrity_verified": True
            }
            
            return {
                "data": artifact_data,
                "metadata": metadata,
                "integrity_verified": True,
                "chain_of_custody_entry": custody_entry
            }
            
        except Exception as e:
            logger.error(f"Failed to retrieve artifact {storage_path}: {e}")
            raise
    
    async def set_legal_hold(self, storage_path: str, enabled: bool, updated_by: str) -> bool:
        """Set or remove legal hold on artifact"""
        
        try:
            # Get current metadata
            response = self.s3_client.head_object(
                Bucket=self.bucket_name,
                Key=storage_path
            )
            
            current_metadata = response.get('Metadata', {})
            
            # Update legal hold status
            current_metadata['legal_hold'] = str(enabled)
            current_metadata['legal_hold_updated_by'] = updated_by
            current_metadata['legal_hold_updated_at'] = datetime.utcnow().isoformat()
            
            # Copy object with updated metadata (S3 metadata update)
            self.s3_client.copy_object(
                Bucket=self.bucket_name,
                Key=storage_path,
                CopySource={'Bucket': self.bucket_name, 'Key': storage_path},
                Metadata=current_metadata,
                MetadataDirective='REPLACE'
            )
            
            logger.info(f"Legal hold {'enabled' if enabled else 'disabled'} for {storage_path}")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to set legal hold for {storage_path}: {e}")
            return False
    
    async def get_artifact_metadata(self, storage_path: str) -> Dict[str, Any]:
        """Get artifact metadata without downloading the file"""
        
        try:
            response = self.s3_client.head_object(
                Bucket=self.bucket_name,
                Key=storage_path
            )
            
            return response.get('Metadata', {})
            
        except Exception as e:
            logger.error(f"Failed to get metadata for {storage_path}: {e}")
            return {}
    
    async def list_incident_artifacts(self, incident_id: str) -> List[Dict[str, Any]]:
        """List all artifacts for an incident"""
        
        try:
            prefix = f"incidents/{incident_id}/"
            
            response = self.s3_client.list_objects_v2(
                Bucket=self.bucket_name,
                Prefix=prefix
            )
            
            artifacts = []
            for obj in response.get('Contents', []):
                # Get metadata for each object
                metadata_response = self.s3_client.head_object(
                    Bucket=self.bucket_name,
                    Key=obj['Key']
                )
                
                artifact_info = {
                    "storage_path": obj['Key'],
                    "size": obj['Size'],
                    "last_modified": obj['LastModified'].isoformat(),
                    "metadata": metadata_response.get('Metadata', {})
                }
                
                artifacts.append(artifact_info)
            
            return artifacts
            
        except Exception as e:
            logger.error(f"Failed to list artifacts for incident {incident_id}: {e}")
            return []
    
    def _calculate_hashes(self, data: bytes) -> Dict[str, str]:
        """Calculate SHA-256 and MD5 hashes for data integrity"""
        
        sha256_hash = hashlib.sha256(data).hexdigest()
        md5_hash = hashlib.md5(data).hexdigest()
        
        return {
            "sha256": sha256_hash,
            "md5": md5_hash
        }
    
    def _generate_storage_path(self, incident_id: str, artifact_name: str, sha256_hash: str) -> str:
        """Generate standardized storage path for artifact"""
        
        # Use date-based partitioning for better organization
        date_partition = datetime.utcnow().strftime("%Y/%m/%d")
        
        # Include hash prefix to avoid collisions
        hash_prefix = sha256_hash[:8]
        
        return f"incidents/{incident_id}/{date_partition}/{hash_prefix}_{artifact_name}"


class ChainOfCustodyService:
    """Service for managing chain of custody records"""
    
    def __init__(self):
        pass
    
    async def add_custody_entry(
        self,
        artifact_id: str,
        action: str,
        user: str,
        details: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Add entry to chain of custody"""
        
        entry = {
            "artifact_id": artifact_id,
            "action": action,
            "timestamp": datetime.utcnow().isoformat(),
            "user": user,
            "details": details,
            "metadata": metadata or {}
        }
        
        # TODO: Store in database
        logger.info(f"Chain of custody entry added for {artifact_id}: {action}")
        
        return entry
    
    async def get_custody_chain(self, artifact_id: str) -> List[Dict[str, Any]]:
        """Get complete chain of custody for an artifact"""
        
        # TODO: Retrieve from database
        return []
    
    async def verify_custody_integrity(self, artifact_id: str) -> bool:
        """Verify integrity of chain of custody"""
        
        # TODO: Implement custody chain verification
        return True
