import pytest
import hashlib
import tempfile
import os
from datetime import datetime
from unittest.mock import AsyncMock, patch

from src.services.artifact_storage import ArtifactStorageService, ChainOfCustodyService


class TestArtifactStorageService:
    """Test suite for artifact storage service"""
    
    @pytest.fixture
    def storage_service(self):
        return ArtifactStorageService()
    
    @pytest.fixture
    def sample_artifact_data(self):
        return b"This is sample artifact data for testing"
    
    @pytest.mark.asyncio
    async def test_store_artifact_success(self, storage_service, sample_artifact_data):
        """Test successful artifact storage"""
        result = await storage_service.store_artifact(
            artifact_data=sample_artifact_data,
            artifact_name="test_artifact.log",
            incident_id="INC-001",
            artifact_type="log_file",
            collected_by="test_collector"
        )
        
        assert "storage_path" in result
        assert "hash_sha256" in result
        assert "hash_md5" in result
        assert result["artifact_name"] == "test_artifact.log"
        assert result["incident_id"] == "INC-001"
        assert result["artifact_type"] == "log_file"
        assert result["collected_by"] == "test_collector"
    
    @pytest.mark.asyncio
    async def test_artifact_hashing_accuracy(self, storage_service, sample_artifact_data):
        """Test artifact hash calculation accuracy"""
        result = await storage_service.store_artifact(
            artifact_data=sample_artifact_data,
            artifact_name="hash_test.bin",
            incident_id="INC-002",
            artifact_type="binary"
        )
        
        # Verify SHA-256 hash
        expected_sha256 = hashlib.sha256(sample_artifact_data).hexdigest()
        assert result["hash_sha256"] == expected_sha256
        
        # Verify MD5 hash
        expected_md5 = hashlib.md5(sample_artifact_data).hexdigest()
        assert result["hash_md5"] == expected_md5
    
    @pytest.mark.asyncio
    async def test_artifact_integrity_verification(self, storage_service, sample_artifact_data):
        """Test artifact integrity verification"""
        # Store artifact
        result = await storage_service.store_artifact(
            artifact_data=sample_artifact_data,
            artifact_name="integrity_test.dat",
            incident_id="INC-003",
            artifact_type="data"
        )
        
        # Verify integrity
        is_valid = await storage_service.verify_artifact_integrity(
            result["storage_path"],
            result["hash_sha256"]
        )
        
        assert is_valid is True
    
    @pytest.mark.asyncio
    async def test_artifact_integrity_failure(self, storage_service):
        """Test artifact integrity verification failure"""
        # Test with invalid hash
        is_valid = await storage_service.verify_artifact_integrity(
            "nonexistent_path",
            "invalid_hash"
        )
        
        assert is_valid is False
    
    @pytest.mark.asyncio
    async def test_worm_storage_immutability(self, storage_service, sample_artifact_data):
        """Test WORM storage immutability"""
        # Store artifact
        result = await storage_service.store_artifact(
            artifact_data=sample_artifact_data,
            artifact_name="worm_test.log",
            incident_id="INC-004",
            artifact_type="log_file"
        )
        
        # Attempt to overwrite should fail
        with pytest.raises(Exception):
            await storage_service.store_artifact(
                artifact_data=b"modified data",
                artifact_name="worm_test.log",
                incident_id="INC-004",
                artifact_type="log_file",
                storage_path=result["storage_path"]  # Same path
            )
    
    @pytest.mark.asyncio
    async def test_legal_hold_functionality(self, storage_service, sample_artifact_data):
        """Test legal hold functionality"""
        # Store artifact with legal hold
        result = await storage_service.store_artifact(
            artifact_data=sample_artifact_data,
            artifact_name="legal_hold_test.doc",
            incident_id="INC-005",
            artifact_type="document",
            legal_hold=True
        )
        
        assert result["legal_hold"] is True
        
        # Verify legal hold prevents deletion
        deletion_result = await storage_service.delete_artifact(result["storage_path"])
        assert deletion_result is False  # Should fail due to legal hold


class TestChainOfCustodyService:
    """Test suite for chain of custody service"""
    
    @pytest.fixture
    def custody_service(self):
        return ChainOfCustodyService()
    
    @pytest.mark.asyncio
    async def test_add_custody_entry(self, custody_service):
        """Test adding chain of custody entry"""
        result = await custody_service.add_custody_entry(
            artifact_id="ART-001",
            action="collected",
            actor="test_collector",
            notes="Initial collection from endpoint"
        )
        
        assert "custody_id" in result
        assert result["artifact_id"] == "ART-001"
        assert result["action"] == "collected"
        assert result["actor"] == "test_collector"
        assert result["notes"] == "Initial collection from endpoint"
        assert "timestamp" in result
    
    @pytest.mark.asyncio
    async def test_get_custody_chain(self, custody_service):
        """Test retrieving custody chain"""
        artifact_id = "ART-002"
        
        # Add multiple custody entries
        await custody_service.add_custody_entry(artifact_id, "collected", "collector1")
        await custody_service.add_custody_entry(artifact_id, "analyzed", "analyst1")
        await custody_service.add_custody_entry(artifact_id, "reviewed", "reviewer1")
        
        # Get custody chain
        chain = await custody_service.get_custody_chain(artifact_id)
        
        assert len(chain) == 3
        assert chain[0]["action"] == "collected"
        assert chain[1]["action"] == "analyzed"
        assert chain[2]["action"] == "reviewed"
    
    @pytest.mark.asyncio
    async def test_custody_chain_integrity(self, custody_service):
        """Test custody chain integrity verification"""
        artifact_id = "ART-003"
        
        # Add custody entries
        await custody_service.add_custody_entry(artifact_id, "collected", "collector1")
        await custody_service.add_custody_entry(artifact_id, "transferred", "system")
        
        # Verify chain integrity
        is_valid = await custody_service.verify_chain_integrity(artifact_id)
        assert is_valid is True
    
    @pytest.mark.asyncio
    async def test_custody_metadata_tracking(self, custody_service):
        """Test custody metadata tracking"""
        result = await custody_service.add_custody_entry(
            artifact_id="ART-004",
            action="processed",
            actor="processor1",
            notes="Automated processing",
            metadata={
                "processing_tool": "forensic_analyzer",
                "version": "1.2.3",
                "checksum_verified": True
            }
        )
        
        assert result["metadata"]["processing_tool"] == "forensic_analyzer"
        assert result["metadata"]["version"] == "1.2.3"
        assert result["metadata"]["checksum_verified"] is True


class TestArtifactEncryption:
    """Test suite for artifact encryption"""
    
    @pytest.mark.asyncio
    async def test_artifact_encryption_decryption(self):
        """Test artifact encryption and decryption"""
        from src.services.encryption_service import encryption_service
        
        # Test data
        original_data = b"Sensitive artifact data that needs encryption"
        tenant_id = "tenant_001"
        
        # Encrypt data
        encrypted_envelope = await encryption_service.encrypt_data(
            original_data, 
            tenant_id,
            {"artifact_type": "sensitive_log"}
        )
        
        # Verify envelope structure
        assert "version" in encrypted_envelope
        assert "algorithm" in encrypted_envelope
        assert "tenant_id" in encrypted_envelope
        assert "encrypted_dek" in encrypted_envelope
        assert "encrypted_data" in encrypted_envelope
        assert "signature" in encrypted_envelope
        
        # Decrypt data
        decrypted_data, metadata = await encryption_service.decrypt_data(encrypted_envelope)
        
        # Verify decryption
        assert decrypted_data == original_data
        assert metadata["artifact_type"] == "sensitive_log"
    
    @pytest.mark.asyncio
    async def test_tenant_isolation(self):
        """Test tenant data isolation"""
        from src.services.encryption_service import encryption_service
        
        data = b"Tenant-specific data"
        tenant1_id = "tenant_001"
        tenant2_id = "tenant_002"
        
        # Encrypt with tenant 1 key
        envelope1 = await encryption_service.encrypt_data(data, tenant1_id)
        
        # Encrypt with tenant 2 key
        envelope2 = await encryption_service.encrypt_data(data, tenant2_id)
        
        # Envelopes should be different (different keys)
        assert envelope1["encrypted_dek"] != envelope2["encrypted_dek"]
        assert envelope1["signature"] != envelope2["signature"]
        
        # Each tenant can only decrypt their own data
        decrypted1, _ = await encryption_service.decrypt_data(envelope1)
        decrypted2, _ = await encryption_service.decrypt_data(envelope2)
        
        assert decrypted1 == data
        assert decrypted2 == data


if __name__ == "__main__":
    pytest.main([__file__])
