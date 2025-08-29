import pytest
import asyncio
import json
import tempfile
import os
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, patch, MagicMock

# E2E test scenarios for complete incident lifecycle


class TestE2EIncidentLifecycle:
    """End-to-end tests for complete incident response lifecycle"""
    
    @pytest.fixture
    def incident_scenario_phishing(self):
        """Complete phishing incident scenario"""
        return {
            "incident_type": "phishing_attack",
            "initial_alert": {
                "timestamp": "2023-12-01T09:00:00Z",
                "source": "email_security",
                "alert_type": "suspicious_email",
                "recipient": "user@company.com",
                "sender": "attacker@malicious-domain.com",
                "subject": "Urgent: Update Your Credentials",
                "attachment": "invoice.xlsx"
            },
            "progression": [
                {
                    "timestamp": "2023-12-01T09:05:00Z",
                    "event": "user_clicked_link",
                    "source": "web_proxy",
                    "details": {
                        "url": "http://malicious-domain.com/login",
                        "user_ip": "192.168.1.100"
                    }
                },
                {
                    "timestamp": "2023-12-01T09:10:00Z",
                    "event": "credential_harvesting",
                    "source": "web_proxy",
                    "details": {
                        "form_submission": True,
                        "credentials_entered": True
                    }
                },
                {
                    "timestamp": "2023-12-01T09:15:00Z",
                    "event": "unauthorized_login_attempt",
                    "source": "identity_provider",
                    "details": {
                        "user_account": "user@company.com",
                        "source_ip": "203.0.113.45",
                        "location": "Unknown"
                    }
                },
                {
                    "timestamp": "2023-12-01T09:20:00Z",
                    "event": "mfa_bypass_attempt",
                    "source": "identity_provider",
                    "details": {
                        "mfa_method": "sms",
                        "bypass_attempted": True
                    }
                }
            ],
            "artifacts": [
                {
                    "type": "email_message",
                    "name": "phishing_email.eml",
                    "content": "suspicious email content with malicious links"
                },
                {
                    "type": "web_logs",
                    "name": "proxy_logs.txt", 
                    "content": "web proxy logs showing malicious domain access"
                },
                {
                    "type": "authentication_logs",
                    "name": "auth_logs.json",
                    "content": "authentication logs showing unauthorized access attempts"
                }
            ],
            "expected_iocs": [
                "malicious-domain.com",
                "203.0.113.45",
                "invoice.xlsx"
            ],
            "expected_techniques": [
                "T1566.001",  # Spearphishing Attachment
                "T1078",      # Valid Accounts
                "T1110"       # Brute Force
            ]
        }
    
    @pytest.fixture
    def incident_scenario_malware(self):
        """Complete malware incident scenario"""
        return {
            "incident_type": "malware_infection",
            "initial_alert": {
                "timestamp": "2023-12-01T14:00:00Z",
                "source": "antivirus",
                "alert_type": "malware_detected",
                "host": "WS-001",
                "file_path": "C:\\temp\\malware.exe",
                "hash": "a1b2c3d4e5f6789012345678901234567890abcdef"
            },
            "progression": [
                {
                    "timestamp": "2023-12-01T14:05:00Z",
                    "event": "process_execution",
                    "source": "edr",
                    "details": {
                        "process_name": "malware.exe",
                        "pid": 1234,
                        "parent_process": "explorer.exe"
                    }
                },
                {
                    "timestamp": "2023-12-01T14:10:00Z",
                    "event": "network_connection",
                    "source": "firewall",
                    "details": {
                        "destination_ip": "185.159.158.177",
                        "destination_port": 443,
                        "protocol": "HTTPS"
                    }
                },
                {
                    "timestamp": "2023-12-01T14:15:00Z",
                    "event": "file_modification",
                    "source": "edr",
                    "details": {
                        "file_path": "C:\\Windows\\System32\\drivers\\etc\\hosts",
                        "action": "modified"
                    }
                },
                {
                    "timestamp": "2023-12-01T14:20:00Z",
                    "event": "registry_modification",
                    "source": "edr",
                    "details": {
                        "registry_key": "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                        "value_name": "Updater",
                        "value_data": "C:\\temp\\malware.exe"
                    }
                }
            ],
            "artifacts": [
                {
                    "type": "malware_sample",
                    "name": "malware.exe",
                    "content": b"malicious_executable_content"
                },
                {
                    "type": "memory_dump",
                    "name": "memory_dump.dmp",
                    "content": "memory dump containing malware artifacts"
                },
                {
                    "type": "network_pcap",
                    "name": "network_capture.pcap",
                    "content": "network packet capture of C2 communication"
                }
            ],
            "expected_iocs": [
                "a1b2c3d4e5f6789012345678901234567890abcdef",
                "185.159.158.177",
                "malware.exe"
            ],
            "expected_techniques": [
                "T1059",      # Command and Scripting Interpreter
                "T1071.001",  # Web Protocols
                "T1547.001"   # Registry Run Keys
            ]
        }
    
    @pytest.mark.asyncio
    async def test_phishing_incident_e2e(self, incident_scenario_phishing):
        """Test complete phishing incident response lifecycle"""
        scenario = incident_scenario_phishing
        incident_id = f"INC-PHISHING-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        
        # Phase 1: Initial Detection and Collection
        collected_artifacts = await self._simulate_artifact_collection(
            incident_id, scenario["artifacts"]
        )
        
        # Verify artifact collection
        assert len(collected_artifacts) == len(scenario["artifacts"])
        
        # Phase 2: Timeline Construction
        timeline = await self._simulate_timeline_correlation(
            incident_id, scenario["initial_alert"], scenario["progression"]
        )
        
        # Verify timeline construction
        assert timeline["incident_id"] == incident_id
        assert timeline["total_events"] == len(scenario["progression"]) + 1  # +1 for initial alert
        
        # Phase 3: Forensic Analysis
        forensic_results = await self._simulate_forensic_analysis(
            incident_id, collected_artifacts, timeline["events"]
        )
        
        # Verify IOC detection
        detected_ioc_values = [ioc["value"] for ioc in forensic_results["iocs"]]
        for expected_ioc in scenario["expected_iocs"]:
            assert any(expected_ioc in detected_value for detected_value in detected_ioc_values), \
                f"Expected IOC {expected_ioc} not detected"
        
        # Verify ATT&CK technique mapping
        detected_techniques = [tech["technique_id"] for tech in forensic_results["attack_techniques"]]
        for expected_technique in scenario["expected_techniques"]:
            assert expected_technique in detected_techniques, \
                f"Expected technique {expected_technique} not detected"
        
        # Phase 4: Report Generation
        final_report = await self._simulate_report_generation(
            incident_id, timeline, forensic_results
        )
        
        # Verify report completeness
        assert final_report["incident_id"] == incident_id
        assert final_report["status"] == "final"
        assert "executive_summary" in final_report["sections"]
        assert "technical_analysis" in final_report["sections"]
        assert "recommendations" in final_report["sections"]
        
        # Verify phishing-specific recommendations
        recommendations = final_report["sections"]["recommendations"]["immediate_actions"]
        phishing_recommendations = [
            r for r in recommendations 
            if "email" in r["action"].lower() or "phishing" in r["action"].lower()
        ]
        assert len(phishing_recommendations) > 0
        
        return {
            "incident_id": incident_id,
            "artifacts": collected_artifacts,
            "timeline": timeline,
            "forensics": forensic_results,
            "report": final_report
        }
    
    @pytest.mark.asyncio
    async def test_malware_incident_e2e(self, incident_scenario_malware):
        """Test complete malware incident response lifecycle"""
        scenario = incident_scenario_malware
        incident_id = f"INC-MALWARE-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        
        # Phase 1: Artifact Collection
        collected_artifacts = await self._simulate_artifact_collection(
            incident_id, scenario["artifacts"]
        )
        
        # Verify malware sample collection
        malware_artifacts = [a for a in collected_artifacts if a["artifact_type"] == "malware_sample"]
        assert len(malware_artifacts) > 0
        
        # Phase 2: Timeline Construction
        timeline = await self._simulate_timeline_correlation(
            incident_id, scenario["initial_alert"], scenario["progression"]
        )
        
        # Verify timeline phases
        assert len(timeline["phases"]) >= 2  # Should identify multiple attack phases
        
        # Phase 3: Forensic Analysis
        forensic_results = await self._simulate_forensic_analysis(
            incident_id, collected_artifacts, timeline["events"]
        )
        
        # Verify malware-specific analysis
        assert forensic_results["risk_score"] >= 7.0  # Malware should be high risk
        
        # Verify process tree reconstruction
        assert len(forensic_results["process_trees"]) > 0
        
        # Phase 4: Report Generation
        final_report = await self._simulate_report_generation(
            incident_id, timeline, forensic_results
        )
        
        # Verify malware-specific content
        technical_details = final_report["sections"]["technical_analysis"]
        assert "malware" in str(technical_details).lower()
        
        return {
            "incident_id": incident_id,
            "artifacts": collected_artifacts,
            "timeline": timeline,
            "forensics": forensic_results,
            "report": final_report
        }
    
    @pytest.mark.asyncio
    async def test_concurrent_incidents_e2e(self, incident_scenario_phishing, incident_scenario_malware):
        """Test handling multiple concurrent incidents"""
        # Start both incidents concurrently
        phishing_task = asyncio.create_task(
            self.test_phishing_incident_e2e(incident_scenario_phishing)
        )
        malware_task = asyncio.create_task(
            self.test_malware_incident_e2e(incident_scenario_malware)
        )
        
        # Wait for both to complete
        phishing_result, malware_result = await asyncio.gather(
            phishing_task, malware_task, return_exceptions=True
        )
        
        # Verify both incidents completed successfully
        assert not isinstance(phishing_result, Exception)
        assert not isinstance(malware_result, Exception)
        
        # Verify incidents are distinct
        assert phishing_result["incident_id"] != malware_result["incident_id"]
        
        # Verify different IOCs detected
        phishing_iocs = set(ioc["value"] for ioc in phishing_result["forensics"]["iocs"])
        malware_iocs = set(ioc["value"] for ioc in malware_result["forensics"]["iocs"])
        
        # Should have some different IOCs
        assert not phishing_iocs.issubset(malware_iocs)
        assert not malware_iocs.issubset(phishing_iocs)
        
        return {
            "phishing": phishing_result,
            "malware": malware_result
        }
    
    @pytest.mark.asyncio
    async def test_incident_escalation_workflow(self, incident_scenario_malware):
        """Test incident escalation and priority handling"""
        scenario = incident_scenario_malware
        incident_id = f"INC-ESCALATION-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        
        # Start with low priority
        initial_priority = "medium"
        
        # Collect artifacts
        collected_artifacts = await self._simulate_artifact_collection(
            incident_id, scenario["artifacts"]
        )
        
        # Build timeline
        timeline = await self._simulate_timeline_correlation(
            incident_id, scenario["initial_alert"], scenario["progression"]
        )
        
        # Perform forensic analysis
        forensic_results = await self._simulate_forensic_analysis(
            incident_id, collected_artifacts, timeline["events"]
        )
        
        # Check if escalation is needed based on risk score
        risk_score = forensic_results["risk_score"]
        
        if risk_score >= 8.0:
            escalated_priority = "critical"
        elif risk_score >= 6.0:
            escalated_priority = "high"
        else:
            escalated_priority = initial_priority
        
        # Simulate escalation
        if escalated_priority != initial_priority:
            await self._simulate_incident_escalation(incident_id, escalated_priority, risk_score)
        
        # Generate report with escalation information
        final_report = await self._simulate_report_generation(
            incident_id, timeline, forensic_results
        )
        
        # Verify escalation is reflected in report
        business_impact = final_report["sections"]["executive_summary"]["business_impact"]
        assert business_impact["severity"] in ["High", "Critical"]
        
        return {
            "incident_id": incident_id,
            "initial_priority": initial_priority,
            "final_priority": escalated_priority,
            "risk_score": risk_score,
            "escalated": escalated_priority != initial_priority
        }
    
    @pytest.mark.asyncio
    async def test_compliance_and_audit_e2e(self, incident_scenario_phishing):
        """Test compliance and audit trail throughout incident lifecycle"""
        scenario = incident_scenario_phishing
        incident_id = f"INC-COMPLIANCE-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        tenant_id = "compliance_tenant"
        
        # Track all audit events
        audit_events = []
        
        # Phase 1: Collection with audit logging
        from src.services.encryption_service import audit_logger
        
        # Log incident creation
        audit_id = await audit_logger.log_event(
            tenant_id,
            "incident_created",
            {"incident_id": incident_id, "incident_type": scenario["incident_type"]},
            user_id="system"
        )
        audit_events.append(audit_id)
        
        # Collect artifacts with encryption and audit
        collected_artifacts = await self._simulate_artifact_collection_with_encryption(
            incident_id, tenant_id, scenario["artifacts"]
        )
        
        # Log artifact collection
        for artifact in collected_artifacts:
            audit_id = await audit_logger.log_event(
                tenant_id,
                "artifact_collected",
                {
                    "incident_id": incident_id,
                    "artifact_id": artifact["storage_path"],
                    "artifact_type": artifact["artifact_type"]
                },
                user_id="collector_system"
            )
            audit_events.append(audit_id)
        
        # Phase 2: Analysis with audit trail
        timeline = await self._simulate_timeline_correlation(
            incident_id, scenario["initial_alert"], scenario["progression"]
        )
        
        # Log timeline analysis
        audit_id = await audit_logger.log_event(
            tenant_id,
            "timeline_analyzed",
            {
                "incident_id": incident_id,
                "total_events": timeline["total_events"],
                "phases_identified": len(timeline["phases"])
            },
            user_id="timeline_analyzer"
        )
        audit_events.append(audit_id)
        
        # Phase 3: Forensic analysis with audit
        forensic_results = await self._simulate_forensic_analysis(
            incident_id, collected_artifacts, timeline["events"]
        )
        
        # Log forensic analysis
        audit_id = await audit_logger.log_event(
            tenant_id,
            "forensic_analysis_completed",
            {
                "incident_id": incident_id,
                "iocs_detected": len(forensic_results["iocs"]),
                "risk_score": forensic_results["risk_score"]
            },
            user_id="forensic_analyst"
        )
        audit_events.append(audit_id)
        
        # Phase 4: Report generation with audit
        final_report = await self._simulate_report_generation(
            incident_id, timeline, forensic_results
        )
        
        # Log report generation
        audit_id = await audit_logger.log_event(
            tenant_id,
            "report_generated",
            {
                "incident_id": incident_id,
                "report_id": final_report["report_id"],
                "quality_score": final_report["metadata"]["quality_score"]
            },
            user_id="report_generator"
        )
        audit_events.append(audit_id)
        
        # Verify audit chain integrity
        chain_valid = await audit_logger.verify_audit_chain(tenant_id)
        
        # Verify compliance requirements
        compliance_checks = {
            "audit_trail_complete": len(audit_events) >= 5,
            "data_encrypted": all("encrypted" in str(a) for a in collected_artifacts),
            "chain_of_custody": all("storage_path" in a for a in collected_artifacts),
            "audit_chain_valid": chain_valid,
            "report_quality": final_report["metadata"]["quality_score"] >= 8.0
        }
        
        return {
            "incident_id": incident_id,
            "audit_events": audit_events,
            "compliance_checks": compliance_checks,
            "all_compliant": all(compliance_checks.values())
        }
    
    # Helper methods for E2E test simulation
    
    async def _simulate_artifact_collection(self, incident_id: str, artifacts: list) -> list:
        """Simulate artifact collection phase"""
        from src.services.artifact_storage import ArtifactStorageService
        
        storage_service = ArtifactStorageService()
        collected_artifacts = []
        
        for artifact in artifacts:
            # Convert content to bytes if it's a string
            if isinstance(artifact["content"], str):
                content = artifact["content"].encode('utf-8')
            else:
                content = artifact["content"]
            
            stored_artifact = await storage_service.store_artifact(
                artifact_data=content,
                artifact_name=artifact["name"],
                incident_id=incident_id,
                artifact_type=artifact["type"],
                collected_by="e2e_test_collector"
            )
            collected_artifacts.append(stored_artifact)
        
        return collected_artifacts
    
    async def _simulate_artifact_collection_with_encryption(self, incident_id: str, tenant_id: str, artifacts: list) -> list:
        """Simulate artifact collection with encryption"""
        from src.services.artifact_storage import ArtifactStorageService
        from src.services.encryption_service import encryption_service
        
        storage_service = ArtifactStorageService()
        collected_artifacts = []
        
        for artifact in artifacts:
            # Convert content to bytes
            if isinstance(artifact["content"], str):
                content = artifact["content"].encode('utf-8')
            else:
                content = artifact["content"]
            
            # Encrypt artifact data
            encrypted_envelope = await encryption_service.encrypt_data(
                content, tenant_id, {"artifact_type": artifact["type"]}
            )
            
            # Store encrypted artifact
            stored_artifact = await storage_service.store_artifact(
                artifact_data=json.dumps(encrypted_envelope).encode('utf-8'),
                artifact_name=artifact["name"],
                incident_id=incident_id,
                artifact_type=artifact["type"],
                collected_by="encrypted_collector"
            )
            
            # Mark as encrypted
            stored_artifact["encrypted"] = True
            collected_artifacts.append(stored_artifact)
        
        return collected_artifacts
    
    async def _simulate_timeline_correlation(self, incident_id: str, initial_alert: dict, progression: list) -> dict:
        """Simulate timeline correlation phase"""
        from src.workers.timeline_enhanced import TimelineWorker
        
        timeline_worker = TimelineWorker()
        
        # Convert alerts and progression to timeline events
        events = []
        
        # Add initial alert
        events.append({
            "id": "initial_alert",
            "timestamp": datetime.fromisoformat(initial_alert["timestamp"].replace('Z', '+00:00')),
            "source": initial_alert["source"],
            "event_type": initial_alert["alert_type"],
            "severity": "high",
            "entities": [initial_alert.get("recipient", "unknown")],
            "data": initial_alert
        })
        
        # Add progression events
        for i, event in enumerate(progression):
            events.append({
                "id": f"progression_{i}",
                "timestamp": datetime.fromisoformat(event["timestamp"].replace('Z', '+00:00')),
                "source": event["source"],
                "event_type": event["event"],
                "severity": "medium",
                "entities": list(event.get("details", {}).values())[:2],  # Limit entities
                "data": event
            })
        
        # Correlate events
        correlated_events = await timeline_worker._correlate_temporal_events(events)
        linked_events = await timeline_worker._link_entities(correlated_events)
        anomalies = await timeline_worker._detect_anomalies(linked_events)
        
        # Build timeline structure
        timeline = await timeline_worker._build_timeline_structure(
            incident_id, linked_events, anomalies
        )
        
        return timeline
    
    async def _simulate_forensic_analysis(self, incident_id: str, artifacts: list, events: list) -> dict:
        """Simulate forensic analysis phase"""
        from src.workers.forensic_enhanced import ForensicWorker
        
        forensic_worker = ForensicWorker()
        
        # Convert artifacts for forensic analysis
        forensic_artifacts = []
        for artifact in artifacts:
            forensic_artifacts.append({
                "id": artifact.get("storage_path", artifact["artifact_name"]),
                "type": artifact["artifact_type"],
                "content": f"forensic analysis content for {artifact['artifact_name']}",
                "hash": artifact.get("hash_sha256", "mock_hash")
            })
        
        # Perform forensic analysis
        iocs = await forensic_worker._detect_iocs(forensic_artifacts, events)
        attack_techniques = await forensic_worker._map_attack_techniques(events, iocs)
        process_trees = await forensic_worker._reconstruct_process_trees(events)
        network_analysis = await forensic_worker._analyze_network_flows(forensic_artifacts, events)
        behavioral_indicators = await forensic_worker._analyze_behavioral_patterns(events)
        risk_score = await forensic_worker._calculate_risk_score(iocs, attack_techniques)
        recommendations = await forensic_worker._generate_recommendations(iocs, attack_techniques)
        
        return {
            "incident_id": incident_id,
            "iocs": iocs,
            "attack_techniques": attack_techniques,
            "process_trees": process_trees,
            "network_analysis": network_analysis,
            "behavioral_indicators": behavioral_indicators,
            "risk_score": risk_score,
            "recommendations": recommendations
        }
    
    async def _simulate_report_generation(self, incident_id: str, timeline: dict, forensic_results: dict) -> dict:
        """Simulate report generation phase"""
        from src.workers.report_enhanced import ReportWorker
        
        report_worker = ReportWorker()
        
        # Prepare incident data
        incident_data = {
            "incident": {
                "id": incident_id,
                "title": f"E2E Test Incident {incident_id}",
                "severity": "high",
                "status": "investigating"
            },
            "timeline": timeline,
            "forensics": forensic_results,
            "artifacts": [],
            "iocs": forensic_results["iocs"]
        }
        
        # Execute CrewAI workflow
        report_sections = await report_worker._execute_crew_workflow(incident_data)
        
        # Compile final report
        final_report = await report_worker._compile_final_report(incident_id, report_sections)
        
        return final_report
    
    async def _simulate_incident_escalation(self, incident_id: str, new_priority: str, risk_score: float):
        """Simulate incident escalation"""
        # In a real system, this would update the incident in the database
        # and potentially trigger notifications
        pass


if __name__ == "__main__":
    pytest.main([__file__])
