from typing import Dict, Any, List, Optional
import structlog
import hashlib
import re
from datetime import datetime
from .base import BaseWorker

logger = structlog.get_logger()

class ForensicWorker(BaseWorker):
    """Worker for forensic analysis and IOC detection"""
    
    def __init__(self):
        super().__init__("forensic", ["forensic.run", "forensic.analyze"])
        self.ioc_patterns = self._load_ioc_patterns()
        self.attack_techniques = self._load_attack_techniques()
    
    async def process_message(self, subject: str, data: Dict[str, Any]):
        """Process forensic analysis messages"""
        incident_id = data.get("incident_id")
        action = data.get("action")
        
        logger.info(f"Processing forensic analysis for incident {incident_id}", action=action)
        
        if action == "analyze":
            await self._run_forensic_analysis(incident_id)
        elif action == "ioc_scan":
            await self._scan_for_iocs(incident_id)
    
    async def _run_forensic_analysis(self, incident_id: str):
        """Run comprehensive forensic analysis"""
        logger.info(f"Running forensic analysis for incident {incident_id}")
        
        try:
            # Get incident artifacts and events
            artifacts = await self._get_incident_artifacts(incident_id)
            events = await self._get_incident_events(incident_id)
            
            # IOC Detection
            iocs = await self._detect_iocs(artifacts, events)
            logger.info(f"Detected {len(iocs)} IOCs")
            
            # ATT&CK Technique Mapping
            attack_techniques = await self._map_attack_techniques(events, iocs)
            logger.info(f"Mapped {len(attack_techniques)} ATT&CK techniques")
            
            # Process Tree Reconstruction
            process_trees = await self._reconstruct_process_trees(events)
            logger.info(f"Reconstructed {len(process_trees)} process trees")
            
            # Network Flow Analysis
            network_analysis = await self._analyze_network_flows(artifacts, events)
            logger.info(f"Analyzed network flows: {len(network_analysis.get('flows', []))} flows")
            
            # Memory/Disk Analysis
            memory_analysis = await self._analyze_memory_artifacts(artifacts)
            disk_analysis = await self._analyze_disk_artifacts(artifacts)
            
            # Behavioral Analysis
            behavioral_indicators = await self._analyze_behavioral_patterns(events)
            
            # Generate forensic report
            forensic_report = {
                "incident_id": incident_id,
                "analysis_timestamp": datetime.utcnow().isoformat(),
                "iocs": iocs,
                "attack_techniques": attack_techniques,
                "process_trees": process_trees,
                "network_analysis": network_analysis,
                "memory_analysis": memory_analysis,
                "disk_analysis": disk_analysis,
                "behavioral_indicators": behavioral_indicators,
                "risk_score": await self._calculate_risk_score(iocs, attack_techniques),
                "recommendations": await self._generate_recommendations(iocs, attack_techniques)
            }
            
            # Store forensic analysis results
            await self._store_forensic_results(forensic_report)
            
            logger.info(f"Forensic analysis completed for incident {incident_id}")
            
        except Exception as e:
            logger.error(f"Forensic analysis failed for incident {incident_id}: {e}")
            raise
    
    async def _scan_for_iocs(self, incident_id: str):
        """Scan artifacts for indicators of compromise"""
        logger.info(f"Scanning for IOCs in incident {incident_id}")
        
        try:
            artifacts = await self._get_incident_artifacts(incident_id)
            events = await self._get_incident_events(incident_id)
            
            iocs = await self._detect_iocs(artifacts, events)
            
            # Correlate with threat intelligence
            enriched_iocs = await self._enrich_iocs_with_threat_intel(iocs)
            
            # Store IOC results
            await self._store_ioc_results(incident_id, enriched_iocs)
            
            logger.info(f"IOC scanning completed: found {len(enriched_iocs)} IOCs")
            
        except Exception as e:
            logger.error(f"IOC scanning failed for incident {incident_id}: {e}")
            raise
    
    async def _simulate_forensic_analysis(self, incident_id: str):
        """Simulate forensic analysis for demo purposes"""
        import asyncio
        
        analysis_steps = [
            "IOC detection",
            "ATT&CK mapping", 
            "Anomaly detection",
            "Process analysis",
            "Network analysis"
        ]
        
        for step in analysis_steps:
            logger.info(f"Executing {step}")
            await asyncio.sleep(1)
            
        logger.info(f"Forensic analysis completed for incident {incident_id}")
