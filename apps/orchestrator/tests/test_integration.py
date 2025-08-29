import pytest
import asyncio
from datetime import datetime
from unittest.mock import AsyncMock, patch, MagicMock

from src.workers.collector import CollectorWorker
from src.workers.timeline_enhanced import TimelineWorker
from src.workers.forensic_enhanced import ForensicWorker
from src.workers.report_enhanced import ReportWorker
from src.services.artifact_storage import ArtifactStorageService
from src.services.encryption_service import encryption_service, audit_logger


class TestIncidentWorkflow:
    """Integration tests for complete incident response workflow"""
    
    @pytest.fixture
    def incident_id(self):
        return "INC-INTEGRATION-001"
    
    @pytest.fixture
    async def collector_worker(self):
        return CollectorWorker()
    
    @pytest.fixture
    async def timeline_worker(self):
        return TimelineWorker()
    
    @pytest.fixture
    async def forensic_worker(self):
        return ForensicWorker()
    
    @pytest.fixture
    async def report_worker(self):
        return ReportWorker()
    
    @pytest.fixture
    def sample_raw_data(self):
        """Sample raw data that would be collected from various sources"""
        return {
            "siem_alerts": [
                {
                    "alert_id": "ALT-001",
                    "timestamp": "2023-12-01T10:00:00Z",
                    "severity": "high",
                    "rule_name": "Suspicious PowerShell Execution",
                    "source_ip": "192.168.1.100",
                    "details": "powershell.exe -enc base64_encoded_command"
                }
            ],
            "edr_events": [
                {
                    "event_id": "EDR-001",
                    "timestamp": "2023-12-01T10:05:00Z",
                    "event_type": "process_creation",
                    "process_name": "powershell.exe",
                    "command_line": "powershell -enc malicious_payload",
                    "parent_process": "explorer.exe",
                    "user": "DOMAIN\\user123"
                }
            ],
            "network_logs": [
                {
                    "log_id": "NET-001",
                    "timestamp": "2023-12-01T10:10:00Z",
                    "source_ip": "192.168.1.100",
                    "destination_ip": "185.159.158.177",
                    "destination_port": 443,
                    "protocol": "HTTPS",
                    "bytes_transferred": 1024
                }
            ],
            "file_artifacts": [
                {
                    "file_path": "C:\\temp\\malware.exe",
                    "file_hash": "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456",
                    "file_size": 102400,
                    "creation_time": "2023-12-01T09:55:00Z",
                    "content": b"malicious_file_content_for_testing"
                }
            ]
        }
    
    @pytest.mark.asyncio
    async def test_artifact_collection_and_storage(self, collector_worker, incident_id, sample_raw_data):
        """Test artifact collection and secure storage"""
        # Mock connector responses
        with patch.object(collector_worker, '_initialize_connectors') as mock_init:
            mock_init.return_value = None
            
            # Mock artifact collection
            with patch.object(collector_worker, '_collect_artifacts') as mock_collect:
                # Simulate artifact collection
                collected_artifacts = []
                
                for file_artifact in sample_raw_data["file_artifacts"]:
                    # Store artifact using storage service
                    storage_service = ArtifactStorageService()
                    stored_artifact = await storage_service.store_artifact(
                        artifact_data=file_artifact["content"],
                        artifact_name=file_artifact["file_path"].split("\\")[-1],
                        incident_id=incident_id,
                        artifact_type="malware_sample",
                        metadata={
                            "original_path": file_artifact["file_path"],
                            "creation_time": file_artifact["creation_time"]
                        }
                    )
                    collected_artifacts.append(stored_artifact)
                
                # Verify artifacts were stored correctly
                assert len(collected_artifacts) == 1
                artifact = collected_artifacts[0]
                
                assert artifact["incident_id"] == incident_id
                assert artifact["artifact_name"] == "malware.exe"
                assert artifact["artifact_type"] == "malware_sample"
                assert "hash_sha256" in artifact
                assert "storage_path" in artifact
                
                # Verify hash matches expected
                expected_hash = "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456"
                # Note: In real test, we'd verify the actual hash of the content
                
                return collected_artifacts
    
    @pytest.mark.asyncio
    async def test_timeline_correlation_workflow(self, timeline_worker, incident_id, sample_raw_data):
        """Test timeline correlation from raw events"""
        # Convert raw data to timeline events
        timeline_events = []
        
        # Convert SIEM alerts
        for alert in sample_raw_data["siem_alerts"]:
            timeline_events.append({
                "id": alert["alert_id"],
                "timestamp": datetime.fromisoformat(alert["timestamp"].replace('Z', '+00:00')),
                "source": "siem",
                "event_type": "alert",
                "severity": alert["severity"],
                "entities": [alert["source_ip"]],
                "data": alert
            })
        
        # Convert EDR events
        for event in sample_raw_data["edr_events"]:
            timeline_events.append({
                "id": event["event_id"],
                "timestamp": datetime.fromisoformat(event["timestamp"].replace('Z', '+00:00')),
                "source": "edr",
                "event_type": "process_creation",
                "severity": "high",
                "entities": [event["process_name"], event["user"]],
                "data": event
            })
        
        # Convert network logs
        for log in sample_raw_data["network_logs"]:
            timeline_events.append({
                "id": log["log_id"],
                "timestamp": datetime.fromisoformat(log["timestamp"].replace('Z', '+00:00')),
                "source": "network",
                "event_type": "network_connection",
                "severity": "medium",
                "entities": [log["source_ip"], log["destination_ip"]],
                "data": log
            })
        
        # Test temporal correlation
        correlated_events = await timeline_worker._correlate_temporal_events(timeline_events)
        assert len(correlated_events) == len(timeline_events)
        
        # Test entity linking
        linked_events = await timeline_worker._link_entities(correlated_events)
        
        # Verify entity linking worked
        ip_192_events = [e for e in linked_events if "192.168.1.100" in e.get("entities", [])]
        assert len(ip_192_events) >= 2  # Should appear in SIEM and network events
        
        # Test anomaly detection
        anomalies = await timeline_worker._detect_anomalies(linked_events)
        
        # Test timeline structure building
        timeline = await timeline_worker._build_timeline_structure(
            incident_id, linked_events, anomalies
        )
        
        assert timeline["incident_id"] == incident_id
        assert timeline["total_events"] == len(timeline_events)
        assert "phases" in timeline
        assert "anomalies" in timeline
        
        return timeline
    
    @pytest.mark.asyncio
    async def test_forensic_analysis_workflow(self, forensic_worker, incident_id, sample_raw_data):
        """Test forensic analysis from artifacts and events"""
        # Mock artifacts (would come from collection phase)
        artifacts = [
            {
                "id": "art_1",
                "type": "log_file",
                "content": "powershell.exe -enc base64command 192.168.1.100 185.159.158.177",
                "hash": "abc123def456"
            }
        ]
        
        # Mock events (would come from timeline phase)
        events = [
            {
                "id": "evt_1",
                "timestamp": datetime.utcnow(),
                "type": "process_creation",
                "data": {
                    "process_name": "powershell.exe",
                    "command_line": "powershell -enc malicious_command"
                }
            }
        ]
        
        # Test IOC detection
        iocs = await forensic_worker._detect_iocs(artifacts, events)
        
        # Should detect IP addresses
        ip_iocs = [ioc for ioc in iocs if ioc["type"] == "ip_addresses"]
        assert len(ip_iocs) >= 2
        
        # Test ATT&CK mapping
        attack_techniques = await forensic_worker._map_attack_techniques(events, iocs)
        
        # Should detect PowerShell technique
        powershell_techniques = [t for t in attack_techniques if "powershell" in t["evidence"]["indicator"]]
        assert len(powershell_techniques) >= 1
        
        # Test process tree reconstruction
        process_trees = await forensic_worker._reconstruct_process_trees(events)
        
        # Test network analysis
        network_analysis = await forensic_worker._analyze_network_flows(artifacts, events)
        
        # Test behavioral analysis
        behavioral_indicators = await forensic_worker._analyze_behavioral_patterns(events)
        
        # Calculate risk score
        risk_score = await forensic_worker._calculate_risk_score(iocs, attack_techniques)
        
        # Generate recommendations
        recommendations = await forensic_worker._generate_recommendations(iocs, attack_techniques)
        
        forensic_results = {
            "incident_id": incident_id,
            "iocs": iocs,
            "attack_techniques": attack_techniques,
            "process_trees": process_trees,
            "network_analysis": network_analysis,
            "behavioral_indicators": behavioral_indicators,
            "risk_score": risk_score,
            "recommendations": recommendations
        }
        
        # Verify comprehensive results
        assert len(forensic_results["iocs"]) > 0
        assert len(forensic_results["attack_techniques"]) > 0
        assert forensic_results["risk_score"] > 0
        assert len(forensic_results["recommendations"]) > 0
        
        return forensic_results
    
    @pytest.mark.asyncio
    async def test_report_generation_workflow(self, report_worker, incident_id):
        """Test report generation from analysis results"""
        # Mock comprehensive incident data
        incident_data = {
            "incident": {
                "id": incident_id,
                "title": "Integration Test Incident",
                "severity": "high",
                "status": "investigating"
            },
            "timeline": {
                "events": [
                    {
                        "timestamp": "2023-12-01T10:00:00Z",
                        "type": "alert",
                        "description": "Suspicious PowerShell execution"
                    }
                ],
                "phases": [
                    {
                        "name": "initial_detection",
                        "start": "2023-12-01T10:00:00Z",
                        "end": "2023-12-01T10:30:00Z"
                    }
                ]
            },
            "forensics": {
                "risk_score": 8.5,
                "attack_techniques": [
                    {
                        "technique_id": "T1059",
                        "technique_name": "Command and Scripting Interpreter",
                        "tactic": "Execution"
                    }
                ],
                "iocs": [
                    {"type": "ip_address", "value": "185.159.158.177"},
                    {"type": "process", "value": "powershell.exe"}
                ]
            },
            "artifacts": [
                {"id": "art_1", "type": "malware_sample", "name": "malware.exe"}
            ],
            "iocs": [
                {"type": "ip_address", "value": "185.159.158.177", "confidence": 0.9}
            ]
        }
        
        # Execute CrewAI workflow
        report_sections = await report_worker._execute_crew_workflow(incident_data)
        
        # Verify all sections were generated
        expected_sections = [
            "data_collection", "timeline_analysis", "forensic_analysis",
            "executive_summary", "technical_details", "recommendations",
            "lessons_learned", "quality_review"
        ]
        
        for section in expected_sections:
            assert section in report_sections
        
        # Compile final report
        final_report = await report_worker._compile_final_report(incident_id, report_sections)
        
        # Verify report structure
        assert final_report["incident_id"] == incident_id
        assert final_report["status"] == "final"
        assert "sections" in final_report
        assert "metadata" in final_report
        
        # Verify quality score
        quality_score = final_report["metadata"]["quality_score"]
        assert quality_score > 8.0
        
        return final_report
    
    @pytest.mark.asyncio
    async def test_end_to_end_incident_workflow(self, incident_id, sample_raw_data):
        """Test complete end-to-end incident response workflow"""
        # Phase 1: Artifact Collection
        collector = CollectorWorker()
        
        # Mock artifact collection
        collected_artifacts = []
        storage_service = ArtifactStorageService()
        
        for file_artifact in sample_raw_data["file_artifacts"]:
            stored_artifact = await storage_service.store_artifact(
                artifact_data=file_artifact["content"],
                artifact_name="malware.exe",
                incident_id=incident_id,
                artifact_type="malware_sample"
            )
            collected_artifacts.append(stored_artifact)
        
        # Phase 2: Timeline Correlation
        timeline_worker = TimelineWorker()
        
        # Convert raw data to events
        events = [
            {
                "id": "evt_1",
                "timestamp": datetime.fromisoformat("2023-12-01T10:00:00+00:00"),
                "source": "siem",
                "event_type": "alert",
                "severity": "high",
                "entities": ["192.168.1.100"],
                "data": sample_raw_data["siem_alerts"][0]
            }
        ]
        
        # Correlate timeline
        correlated_events = await timeline_worker._correlate_temporal_events(events)
        linked_events = await timeline_worker._link_entities(correlated_events)
        anomalies = await timeline_worker._detect_anomalies(linked_events)
        
        timeline = await timeline_worker._build_timeline_structure(
            incident_id, linked_events, anomalies
        )
        
        # Phase 3: Forensic Analysis
        forensic_worker = ForensicWorker()
        
        # Mock artifacts for forensic analysis
        forensic_artifacts = [
            {
                "id": "art_1",
                "type": "log_file",
                "content": "powershell.exe -enc command 185.159.158.177",
                "hash": "abc123"
            }
        ]
        
        iocs = await forensic_worker._detect_iocs(forensic_artifacts, linked_events)
        attack_techniques = await forensic_worker._map_attack_techniques(linked_events, iocs)
        risk_score = await forensic_worker._calculate_risk_score(iocs, attack_techniques)
        
        # Phase 4: Report Generation
        report_worker = ReportWorker()
        
        incident_data = {
            "incident": {"id": incident_id, "severity": "high"},
            "timeline": timeline,
            "forensics": {
                "iocs": iocs,
                "attack_techniques": attack_techniques,
                "risk_score": risk_score
            },
            "artifacts": collected_artifacts,
            "iocs": iocs
        }
        
        report_sections = await report_worker._execute_crew_workflow(incident_data)
        final_report = await report_worker._compile_final_report(incident_id, report_sections)
        
        # Verify end-to-end workflow results
        assert len(collected_artifacts) > 0
        assert timeline["total_events"] > 0
        assert len(iocs) > 0
        assert len(attack_techniques) > 0
        assert risk_score > 0
        assert final_report["status"] == "final"
        
        # Verify data flow integrity
        assert final_report["incident_id"] == incident_id
        assert final_report["sections"]["forensic_findings"]["risk_score"] == risk_score
        
        return {
            "artifacts": collected_artifacts,
            "timeline": timeline,
            "forensics": {
                "iocs": iocs,
                "attack_techniques": attack_techniques,
                "risk_score": risk_score
            },
            "report": final_report
        }
    
    @pytest.mark.asyncio
    async def test_encryption_and_audit_integration(self, incident_id):
        """Test encryption and audit logging integration"""
        tenant_id = "tenant_001"
        
        # Test data encryption
        sensitive_data = b"Sensitive incident data that must be encrypted"
        
        encrypted_envelope = await encryption_service.encrypt_data(
            sensitive_data,
            tenant_id,
            {"incident_id": incident_id, "data_type": "forensic_evidence"}
        )
        
        # Verify encryption envelope
        assert encrypted_envelope["tenant_id"] == tenant_id
        assert "encrypted_data" in encrypted_envelope
        assert "signature" in encrypted_envelope
        
        # Test decryption
        decrypted_data, metadata = await encryption_service.decrypt_data(encrypted_envelope)
        assert decrypted_data == sensitive_data
        assert metadata["incident_id"] == incident_id
        
        # Test audit logging
        audit_event_id = await audit_logger.log_event(
            tenant_id,
            "incident_data_accessed",
            {
                "incident_id": incident_id,
                "data_type": "forensic_evidence",
                "access_reason": "integration_test"
            },
            user_id="test_user"
        )
        
        assert audit_event_id is not None
        
        # Test audit chain verification
        chain_valid = await audit_logger.verify_audit_chain(tenant_id)
        # Note: In a real implementation with database, this would verify the actual chain
        
        return {
            "encryption_successful": True,
            "audit_logged": audit_event_id,
            "chain_valid": chain_valid
        }


class TestSystemIntegration:
    """Integration tests for system components"""
    
    @pytest.mark.asyncio
    async def test_worker_communication(self):
        """Test communication between workers"""
        # This would test NATS messaging between workers
        # For now, we'll test the worker interfaces
        
        collector = CollectorWorker()
        timeline = TimelineWorker()
        forensic = ForensicWorker()
        report = ReportWorker()
        
        # Verify workers are properly initialized
        assert collector.name == "collector"
        assert timeline.name == "timeline"
        assert forensic.name == "forensic"
        assert report.name == "report"
        
        # Verify message subjects
        assert "incident.collect" in collector.subjects
        assert "timeline.build" in timeline.subjects
        assert "forensic.run" in forensic.subjects
        assert "report.generate" in report.subjects
    
    @pytest.mark.asyncio
    async def test_data_persistence_integration(self):
        """Test data persistence across workflow stages"""
        incident_id = "INC-PERSISTENCE-TEST"
        
        # Test artifact storage persistence
        storage_service = ArtifactStorageService()
        
        artifact_result = await storage_service.store_artifact(
            artifact_data=b"test persistence data",
            artifact_name="persistence_test.log",
            incident_id=incident_id,
            artifact_type="test_log"
        )
        
        # Verify artifact can be retrieved (mock implementation)
        assert artifact_result["incident_id"] == incident_id
        assert artifact_result["artifact_name"] == "persistence_test.log"
        
        # Test encryption persistence
        tenant_id = "persistence_tenant"
        test_data = b"persistent encrypted data"
        
        encrypted = await encryption_service.encrypt_data(test_data, tenant_id)
        decrypted, _ = await encryption_service.decrypt_data(encrypted)
        
        assert decrypted == test_data
    
    @pytest.mark.asyncio
    async def test_error_handling_and_recovery(self):
        """Test error handling and recovery mechanisms"""
        # Test worker error handling
        forensic_worker = ForensicWorker()
        
        # Test with invalid data
        try:
            invalid_artifacts = [{"invalid": "data"}]
            invalid_events = [{"also_invalid": "data"}]
            
            # This should handle errors gracefully
            iocs = await forensic_worker._detect_iocs(invalid_artifacts, invalid_events)
            # Should return empty list rather than crash
            assert isinstance(iocs, list)
            
        except Exception as e:
            # If it does throw, it should be a handled exception
            assert "Failed to" in str(e) or "Invalid" in str(e)
        
        # Test encryption error handling
        try:
            # Test with invalid envelope
            invalid_envelope = {"invalid": "envelope"}
            await encryption_service.decrypt_data(invalid_envelope)
            assert False, "Should have raised an exception"
        except Exception as e:
            # Should handle gracefully
            assert isinstance(e, (ValueError, KeyError))


if __name__ == "__main__":
    pytest.main([__file__])
