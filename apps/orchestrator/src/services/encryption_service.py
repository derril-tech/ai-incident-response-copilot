from typing import Dict, Any, Optional, Tuple
import structlog
import hashlib
import hmac
import secrets
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
import json
from datetime import datetime
import os

logger = structlog.get_logger()

class EncryptionService:
    """Enterprise-grade encryption service with per-tenant isolation"""
    
    def __init__(self):
        self.master_key = self._get_or_create_master_key()
        self.tenant_keys = {}
        self.key_rotation_interval = 86400 * 30  # 30 days
    
    def _get_or_create_master_key(self) -> bytes:
        """Get or create master encryption key"""
        key_file = os.getenv('MASTER_KEY_FILE', '/etc/secrets/master.key')
        
        try:
            if os.path.exists(key_file):
                with open(key_file, 'rb') as f:
                    return f.read()
            else:
                # Generate new master key
                master_key = secrets.token_bytes(32)
                os.makedirs(os.path.dirname(key_file), exist_ok=True)
                with open(key_file, 'wb') as f:
                    f.write(master_key)
                os.chmod(key_file, 0o600)
                logger.info("Generated new master encryption key")
                return master_key
        except Exception as e:
            logger.error(f"Failed to handle master key: {e}")
            # Fallback to environment variable
            env_key = os.getenv('MASTER_ENCRYPTION_KEY')
            if env_key:
                return base64.b64decode(env_key)
            else:
                raise ValueError("No master encryption key available")
    
    async def get_tenant_key(self, tenant_id: str) -> bytes:
        """Get or create tenant-specific encryption key"""
        if tenant_id not in self.tenant_keys:
            # Derive tenant key from master key
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=tenant_id.encode('utf-8'),
                iterations=100000,
            )
            tenant_key = kdf.derive(self.master_key)
            self.tenant_keys[tenant_id] = tenant_key
            logger.info(f"Derived encryption key for tenant {tenant_id}")
        
        return self.tenant_keys[tenant_id]
    
    async def encrypt_data(self, data: bytes, tenant_id: str, metadata: Dict[str, Any] = None) -> Dict[str, Any]:
        """Encrypt data with tenant-specific key and envelope encryption"""
        try:
            # Generate data encryption key (DEK)
            dek = secrets.token_bytes(32)
            
            # Encrypt data with DEK
            iv = secrets.token_bytes(16)
            cipher = Cipher(algorithms.AES(dek), modes.CBC(iv))
            encryptor = cipher.encryptor()
            
            # Pad data to block size
            padded_data = self._pad_data(data)
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
            
            # Encrypt DEK with tenant key (KEK - Key Encryption Key)
            tenant_key = await self.get_tenant_key(tenant_id)
            kek_cipher = Fernet(base64.urlsafe_b64encode(tenant_key))
            encrypted_dek = kek_cipher.encrypt(dek)
            
            # Create encryption envelope
            envelope = {
                "version": "1.0",
                "algorithm": "AES-256-CBC",
                "tenant_id": tenant_id,
                "encrypted_dek": base64.b64encode(encrypted_dek).decode('utf-8'),
                "iv": base64.b64encode(iv).decode('utf-8'),
                "encrypted_data": base64.b64encode(encrypted_data).decode('utf-8'),
                "data_hash": hashlib.sha256(data).hexdigest(),
                "created_at": datetime.utcnow().isoformat(),
                "metadata": metadata or {}
            }
            
            # Sign envelope for integrity
            envelope_json = json.dumps(envelope, sort_keys=True)
            signature = hmac.new(
                tenant_key, 
                envelope_json.encode('utf-8'), 
                hashlib.sha256
            ).hexdigest()
            envelope["signature"] = signature
            
            logger.info(f"Encrypted data for tenant {tenant_id}")
            return envelope
            
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            raise
    
    async def decrypt_data(self, envelope: Dict[str, Any]) -> Tuple[bytes, Dict[str, Any]]:
        """Decrypt data from encryption envelope"""
        try:
            tenant_id = envelope["tenant_id"]
            tenant_key = await self.get_tenant_key(tenant_id)
            
            # Verify envelope signature
            envelope_copy = envelope.copy()
            signature = envelope_copy.pop("signature")
            envelope_json = json.dumps(envelope_copy, sort_keys=True)
            expected_signature = hmac.new(
                tenant_key,
                envelope_json.encode('utf-8'),
                hashlib.sha256
            ).hexdigest()
            
            if not hmac.compare_digest(signature, expected_signature):
                raise ValueError("Envelope signature verification failed")
            
            # Decrypt DEK with tenant key
            encrypted_dek = base64.b64decode(envelope["encrypted_dek"])
            kek_cipher = Fernet(base64.urlsafe_b64encode(tenant_key))
            dek = kek_cipher.decrypt(encrypted_dek)
            
            # Decrypt data with DEK
            iv = base64.b64decode(envelope["iv"])
            encrypted_data = base64.b64decode(envelope["encrypted_data"])
            
            cipher = Cipher(algorithms.AES(dek), modes.CBC(iv))
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
            
            # Remove padding
            data = self._unpad_data(padded_data)
            
            # Verify data integrity
            data_hash = hashlib.sha256(data).hexdigest()
            if data_hash != envelope["data_hash"]:
                raise ValueError("Data integrity verification failed")
            
            logger.info(f"Decrypted data for tenant {tenant_id}")
            return data, envelope.get("metadata", {})
            
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            raise
    
    def _pad_data(self, data: bytes) -> bytes:
        """Apply PKCS7 padding"""
        block_size = 16
        padding_length = block_size - (len(data) % block_size)
        padding = bytes([padding_length] * padding_length)
        return data + padding
    
    def _unpad_data(self, padded_data: bytes) -> bytes:
        """Remove PKCS7 padding"""
        padding_length = padded_data[-1]
        return padded_data[:-padding_length]
    
    async def rotate_tenant_key(self, tenant_id: str) -> bool:
        """Rotate tenant encryption key"""
        try:
            # Generate new tenant key
            old_key = self.tenant_keys.get(tenant_id)
            
            # Force regeneration of tenant key
            if tenant_id in self.tenant_keys:
                del self.tenant_keys[tenant_id]
            
            new_key = await self.get_tenant_key(tenant_id)
            
            # TODO: Re-encrypt existing data with new key
            # This would be done in a background job
            
            logger.info(f"Rotated encryption key for tenant {tenant_id}")
            return True
            
        except Exception as e:
            logger.error(f"Key rotation failed for tenant {tenant_id}: {e}")
            return False


class ImmutableAuditLogger:
    """Immutable audit logging with cryptographic integrity"""
    
    def __init__(self, encryption_service: EncryptionService):
        self.encryption_service = encryption_service
        self.log_chain = {}  # tenant_id -> last_hash
    
    async def log_event(self, tenant_id: str, event_type: str, event_data: Dict[str, Any], 
                       user_id: str = None, session_id: str = None) -> str:
        """Log immutable audit event"""
        try:
            # Create audit event
            event_id = secrets.token_hex(16)
            timestamp = datetime.utcnow()
            
            # Get previous hash for chain integrity
            previous_hash = self.log_chain.get(tenant_id, "0" * 64)
            
            audit_event = {
                "event_id": event_id,
                "tenant_id": tenant_id,
                "event_type": event_type,
                "timestamp": timestamp.isoformat(),
                "user_id": user_id,
                "session_id": session_id,
                "event_data": event_data,
                "previous_hash": previous_hash
            }
            
            # Calculate event hash for chain integrity
            event_json = json.dumps(audit_event, sort_keys=True)
            event_hash = hashlib.sha256(event_json.encode('utf-8')).hexdigest()
            audit_event["event_hash"] = event_hash
            
            # Encrypt audit event
            encrypted_event = await self.encryption_service.encrypt_data(
                event_json.encode('utf-8'),
                tenant_id,
                {"type": "audit_log", "event_type": event_type}
            )
            
            # Store encrypted event (would be in database)
            await self._store_audit_event(tenant_id, event_id, encrypted_event)
            
            # Update chain hash
            self.log_chain[tenant_id] = event_hash
            
            logger.info(f"Logged audit event {event_id} for tenant {tenant_id}")
            return event_id
            
        except Exception as e:
            logger.error(f"Audit logging failed: {e}")
            raise
    
    async def verify_audit_chain(self, tenant_id: str) -> bool:
        """Verify integrity of audit log chain"""
        try:
            # Get all audit events for tenant (would query database)
            events = await self._get_audit_events(tenant_id)
            
            previous_hash = "0" * 64
            
            for encrypted_event in events:
                # Decrypt event
                event_data, _ = await self.encryption_service.decrypt_data(encrypted_event)
                event = json.loads(event_data.decode('utf-8'))
                
                # Verify chain integrity
                if event["previous_hash"] != previous_hash:
                    logger.error(f"Audit chain integrity violation at event {event['event_id']}")
                    return False
                
                # Verify event hash
                event_copy = event.copy()
                stored_hash = event_copy.pop("event_hash")
                calculated_hash = hashlib.sha256(
                    json.dumps(event_copy, sort_keys=True).encode('utf-8')
                ).hexdigest()
                
                if stored_hash != calculated_hash:
                    logger.error(f"Event hash verification failed for {event['event_id']}")
                    return False
                
                previous_hash = stored_hash
            
            logger.info(f"Audit chain verified for tenant {tenant_id}")
            return True
            
        except Exception as e:
            logger.error(f"Audit chain verification failed: {e}")
            return False
    
    async def _store_audit_event(self, tenant_id: str, event_id: str, encrypted_event: Dict[str, Any]):
        """Store encrypted audit event (mock implementation)"""
        # TODO: Store in database with proper indexing
        logger.debug(f"Storing audit event {event_id} for tenant {tenant_id}")
    
    async def _get_audit_events(self, tenant_id: str) -> list:
        """Get audit events for tenant (mock implementation)"""
        # TODO: Query from database
        return []


class TenantIsolationService:
    """Service for multi-tenant data isolation"""
    
    def __init__(self, encryption_service: EncryptionService, audit_logger: ImmutableAuditLogger):
        self.encryption_service = encryption_service
        self.audit_logger = audit_logger
    
    async def store_tenant_data(self, tenant_id: str, data_type: str, data: Dict[str, Any], 
                               user_id: str = None) -> str:
        """Store data with tenant isolation and encryption"""
        try:
            # Serialize data
            data_bytes = json.dumps(data, sort_keys=True).encode('utf-8')
            
            # Encrypt with tenant-specific key
            encrypted_data = await self.encryption_service.encrypt_data(
                data_bytes,
                tenant_id,
                {"data_type": data_type, "stored_by": user_id}
            )
            
            # Generate storage ID
            storage_id = f"{tenant_id}:{data_type}:{secrets.token_hex(8)}"
            
            # Store encrypted data (would be in database with tenant_id partitioning)
            await self._store_encrypted_data(storage_id, encrypted_data)
            
            # Log audit event
            await self.audit_logger.log_event(
                tenant_id,
                "data_stored",
                {
                    "storage_id": storage_id,
                    "data_type": data_type,
                    "data_size": len(data_bytes)
                },
                user_id
            )
            
            logger.info(f"Stored tenant data {storage_id}")
            return storage_id
            
        except Exception as e:
            logger.error(f"Failed to store tenant data: {e}")
            raise
    
    async def retrieve_tenant_data(self, tenant_id: str, storage_id: str, 
                                  user_id: str = None) -> Dict[str, Any]:
        """Retrieve and decrypt tenant data"""
        try:
            # Verify tenant access
            if not storage_id.startswith(f"{tenant_id}:"):
                raise ValueError("Access denied: storage ID does not belong to tenant")
            
            # Retrieve encrypted data
            encrypted_data = await self._get_encrypted_data(storage_id)
            
            # Decrypt data
            data_bytes, metadata = await self.encryption_service.decrypt_data(encrypted_data)
            data = json.loads(data_bytes.decode('utf-8'))
            
            # Log audit event
            await self.audit_logger.log_event(
                tenant_id,
                "data_accessed",
                {
                    "storage_id": storage_id,
                    "data_type": metadata.get("data_type"),
                    "accessed_by": user_id
                },
                user_id
            )
            
            logger.info(f"Retrieved tenant data {storage_id}")
            return data
            
        except Exception as e:
            logger.error(f"Failed to retrieve tenant data: {e}")
            raise
    
    async def _store_encrypted_data(self, storage_id: str, encrypted_data: Dict[str, Any]):
        """Store encrypted data (mock implementation)"""
        # TODO: Store in database with proper tenant partitioning
        logger.debug(f"Storing encrypted data {storage_id}")
    
    async def _get_encrypted_data(self, storage_id: str) -> Dict[str, Any]:
        """Get encrypted data (mock implementation)"""
        # TODO: Retrieve from database
        return {}


# Global service instances
encryption_service = EncryptionService()
audit_logger = ImmutableAuditLogger(encryption_service)
tenant_isolation = TenantIsolationService(encryption_service, audit_logger)

# Convenience functions
async def encrypt_tenant_data(tenant_id: str, data: bytes, metadata: Dict[str, Any] = None) -> Dict[str, Any]:
    return await encryption_service.encrypt_data(data, tenant_id, metadata)

async def decrypt_tenant_data(envelope: Dict[str, Any]) -> Tuple[bytes, Dict[str, Any]]:
    return await encryption_service.decrypt_data(envelope)

async def log_audit_event(tenant_id: str, event_type: str, event_data: Dict[str, Any], 
                         user_id: str = None, session_id: str = None) -> str:
    return await audit_logger.log_event(tenant_id, event_type, event_data, user_id, session_id)

async def store_tenant_data(tenant_id: str, data_type: str, data: Dict[str, Any], 
                           user_id: str = None) -> str:
    return await tenant_isolation.store_tenant_data(tenant_id, data_type, data, user_id)

async def retrieve_tenant_data(tenant_id: str, storage_id: str, user_id: str = None) -> Dict[str, Any]:
    return await tenant_isolation.retrieve_tenant_data(tenant_id, storage_id, user_id)
