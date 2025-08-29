from typing import Dict, Any, List, Optional
import structlog
import hashlib
import re
from datetime import datetime
from .base import BaseWorker

logger = structlog.get_logger()

class ForensicWorker(BaseWorker):
    """Enhanced worker for forensic analysis and IOC detection"""
    
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
    
    def _load_ioc_patterns(self) -> Dict[str, Any]:
        """Load IOC detection patterns"""
        return {
            "ip_addresses": r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            "domains": r'\b[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\b',
            "urls": r'https?://[^\s<>"{}|\\^`\[\]]+',
            "md5_hashes": r'\b[a-fA-F0-9]{32}\b',
            "sha1_hashes": r'\b[a-fA-F0-9]{40}\b',
            "sha256_hashes": r'\b[a-fA-F0-9]{64}\b',
            "email_addresses": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            "file_paths": r'[A-Za-z]:\\[^<>:"|?*\r\n]*|\/[^<>:"|?*\r\n]*',
            "registry_keys": r'HKEY_[A-Z_]+\\[^<>:"|?*\r\n]*'
        }
    
    def _load_attack_techniques(self) -> Dict[str, Dict[str, Any]]:
        """Load MITRE ATT&CK technique mappings"""
        return {
            "T1055": {
                "name": "Process Injection",
                "tactic": "Defense Evasion",
                "description": "Adversaries may inject code into processes",
                "indicators": ["process_hollowing", "dll_injection", "process_doppelganging"]
            },
            "T1059": {
                "name": "Command and Scripting Interpreter",
                "tactic": "Execution",
                "description": "Adversaries may abuse command and script interpreters",
                "indicators": ["powershell", "cmd", "bash", "python", "wscript"]
            },
            "T1071": {
                "name": "Application Layer Protocol",
                "tactic": "Command and Control",
                "description": "Adversaries may communicate using OSI application layer protocols",
                "indicators": ["http", "https", "dns", "ftp"]
            },
            "T1083": {
                "name": "File and Directory Discovery",
                "tactic": "Discovery",
                "description": "Adversaries may enumerate files and directories",
                "indicators": ["dir", "ls", "find", "tree"]
            },
            "T1090": {
                "name": "Proxy",
                "tactic": "Command and Control",
                "description": "Adversaries may use a connection proxy",
                "indicators": ["proxy", "socks", "tor"]
            },
            "T1105": {
                "name": "Ingress Tool Transfer",
                "tactic": "Command and Control",
                "description": "Adversaries may transfer tools or other files",
                "indicators": ["download", "wget", "curl", "certutil"]
            },
            "T1566": {
                "name": "Phishing",
                "tactic": "Initial Access",
                "description": "Adversaries may send phishing messages",
                "indicators": ["email", "attachment", "link", "spearphishing"]
            }
        }
    
    async def _get_incident_artifacts(self, incident_id: str) -> List[Dict[str, Any]]:
        """Get artifacts for incident"""
        # TODO: Query artifact storage service
        return [
            {
                "id": f"artifact_{i}",
                "type": "log_file",
                "name": f"system_{i}.log",
                "content": f"Sample log content with suspicious activity {i} powershell.exe -enc base64command",
                "hash": hashlib.sha256(f"content_{i}".encode()).hexdigest()
            }
            for i in range(5)
        ]
    
    async def _get_incident_events(self, incident_id: str) -> List[Dict[str, Any]]:
        """Get events for incident"""
        # TODO: Query timeline service
        return [
            {
                "id": f"event_{i}",
                "timestamp": datetime.utcnow(),
                "type": "process_creation",
                "data": {
                    "process_name": "powershell.exe" if i % 2 == 0 else "cmd.exe",
                    "command_line": f"powershell -enc {i}" if i % 2 == 0 else f"cmd /c dir {i}",
                    "parent_process": "explorer.exe",
                    "user": f"user_{i}"
                }
            }
            for i in range(10)
        ]
    
    async def _detect_iocs(self, artifacts: List[Dict[str, Any]], events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect indicators of compromise"""
        iocs = []
        
        # Scan artifacts for IOCs
        for artifact in artifacts:
            content = artifact.get('content', '')
            artifact_iocs = await self._scan_content_for_iocs(content, artifact['id'])
            iocs.extend(artifact_iocs)
        
        # Scan events for IOCs
        for event in events:
            event_data = str(event.get('data', {}))
            event_iocs = await self._scan_content_for_iocs(event_data, event['id'])
            iocs.extend(event_iocs)
        
        # Deduplicate IOCs
        unique_iocs = []
        seen_values = set()
        
        for ioc in iocs:
            if ioc['value'] not in seen_values:
                unique_iocs.append(ioc)
                seen_values.add(ioc['value'])
        
        return unique_iocs
    
    async def _scan_content_for_iocs(self, content: str, source_id: str) -> List[Dict[str, Any]]:
        """Scan content for IOC patterns"""
        iocs = []
        
        for ioc_type, pattern in self.ioc_patterns.items():
            matches = re.findall(pattern, content)
            
            for match in matches:
                ioc = {
                    "type": ioc_type,
                    "value": match,
                    "source": source_id,
                    "confidence": self._calculate_ioc_confidence(ioc_type, match),
                    "first_seen": datetime.utcnow().isoformat(),
                    "threat_level": "unknown"
                }
                iocs.append(ioc)
        
        return iocs
    
    def _calculate_ioc_confidence(self, ioc_type: str, value: str) -> float:
        """Calculate confidence score for IOC"""
        # Simple confidence scoring
        confidence_scores = {
            "sha256_hashes": 0.9,
            "md5_hashes": 0.8,
            "ip_addresses": 0.7,
            "domains": 0.6,
            "urls": 0.8,
            "email_addresses": 0.5,
            "file_paths": 0.4,
            "registry_keys": 0.6
        }
        
        base_confidence = confidence_scores.get(ioc_type, 0.5)
        
        # Adjust based on value characteristics
        if ioc_type == "domains" and any(suspicious in value.lower() for suspicious in ["temp", "tmp", "test", "malware"]):
            base_confidence += 0.2
        
        return min(base_confidence, 1.0)
    
    async def _map_attack_techniques(self, events: List[Dict[str, Any]], iocs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Map events and IOCs to MITRE ATT&CK techniques"""
        mapped_techniques = []
        
        for event in events:
            event_data = str(event.get('data', {})).lower()
            
            for technique_id, technique_info in self.attack_techniques.items():
                for indicator in technique_info['indicators']:
                    if indicator in event_data:
                        mapped_techniques.append({
                            "technique_id": technique_id,
                            "technique_name": technique_info['name'],
                            "tactic": technique_info['tactic'],
                            "description": technique_info['description'],
                            "evidence": {
                                "event_id": event['id'],
                                "indicator": indicator,
                                "confidence": 0.8
                            },
                            "timestamp": event.get('timestamp', datetime.utcnow()).isoformat()
                        })
        
        return mapped_techniques
    
    async def _reconstruct_process_trees(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Reconstruct process execution trees"""
        process_trees = []
        processes = {}
        
        # Build process hierarchy
        for event in events:
            if event.get('type') == 'process_creation':
                data = event.get('data', {})
                process_name = data.get('process_name')
                parent_process = data.get('parent_process')
                
                if process_name:
                    processes[process_name] = {
                        "name": process_name,
                        "parent": parent_process,
                        "command_line": data.get('command_line'),
                        "user": data.get('user'),
                        "timestamp": event.get('timestamp'),
                        "children": []
                    }
        
        # Build tree structure
        for process_name, process_info in processes.items():
            parent_name = process_info['parent']
            if parent_name and parent_name in processes:
                processes[parent_name]['children'].append(process_info)
            else:
                # Root process
                process_trees.append(process_info)
        
        return process_trees
    
    async def _analyze_network_flows(self, artifacts: List[Dict[str, Any]], events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze network flows and connections"""
        flows = []
        
        # Extract network-related IOCs
        for artifact in artifacts:
            content = artifact.get('content', '')
            
            # Find IP addresses and domains
            ips = re.findall(self.ioc_patterns['ip_addresses'], content)
            domains = re.findall(self.ioc_patterns['domains'], content)
            
            for ip in ips:
                flows.append({
                    "type": "ip_connection",
                    "destination": ip,
                    "source_artifact": artifact['id'],
                    "protocol": "unknown",
                    "port": "unknown",
                    "direction": "outbound"
                })
            
            for domain in domains:
                flows.append({
                    "type": "dns_query",
                    "destination": domain,
                    "source_artifact": artifact['id'],
                    "protocol": "dns",
                    "port": "53",
                    "direction": "outbound"
                })
        
        return {
            "flows": flows,
            "unique_destinations": len(set(flow['destination'] for flow in flows)),
            "suspicious_connections": [flow for flow in flows if self._is_suspicious_connection(flow)]
        }
    
    def _is_suspicious_connection(self, flow: Dict[str, Any]) -> bool:
        """Determine if network connection is suspicious"""
        destination = flow.get('destination', '').lower()
        
        # Simple heuristics for suspicious connections
        suspicious_indicators = [
            'temp', 'tmp', 'test', 'malware', 'c2', 'command', 'control',
            'bot', 'trojan', 'virus', 'hack', 'exploit'
        ]
        
        return any(indicator in destination for indicator in suspicious_indicators)
    
    async def _analyze_memory_artifacts(self, artifacts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze memory dump artifacts"""
        memory_artifacts = [a for a in artifacts if a.get('type') == 'memory_dump']
        
        analysis = {
            "total_dumps": len(memory_artifacts),
            "suspicious_processes": [],
            "injected_code": [],
            "network_connections": []
        }
        
        # Simulate memory analysis
        for artifact in memory_artifacts:
            # Look for suspicious process names
            content = artifact.get('content', '')
            if 'powershell' in content.lower() or 'cmd' in content.lower():
                analysis['suspicious_processes'].append({
                    "process": "powershell.exe",
                    "pid": 1234,
                    "suspicious_indicators": ["encoded_command", "bypass_execution_policy"]
                })
        
        return analysis
    
    async def _analyze_disk_artifacts(self, artifacts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze disk image artifacts"""
        disk_artifacts = [a for a in artifacts if a.get('type') == 'disk_image']
        
        analysis = {
            "total_images": len(disk_artifacts),
            "suspicious_files": [],
            "persistence_mechanisms": [],
            "deleted_files": []
        }
        
        # Simulate disk analysis
        for artifact in disk_artifacts:
            analysis['suspicious_files'].append({
                "path": "C:\\temp\\malware.exe",
                "hash": "abc123def456",
                "size": 102400,
                "created": datetime.utcnow().isoformat(),
                "threat_level": "high"
            })
        
        return analysis
    
    async def _analyze_behavioral_patterns(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze behavioral patterns in events"""
        patterns = []
        
        # Detect rapid process creation
        process_events = [e for e in events if e.get('type') == 'process_creation']
        if len(process_events) > 5:
            patterns.append({
                "pattern": "rapid_process_creation",
                "description": f"Detected {len(process_events)} process creation events",
                "severity": "medium",
                "confidence": 0.7
            })
        
        # Detect PowerShell usage
        powershell_events = [e for e in process_events if 'powershell' in str(e.get('data', {})).lower()]
        if powershell_events:
            patterns.append({
                "pattern": "powershell_execution",
                "description": f"Detected {len(powershell_events)} PowerShell execution events",
                "severity": "high",
                "confidence": 0.8
            })
        
        return patterns
    
    async def _calculate_risk_score(self, iocs: List[Dict[str, Any]], attack_techniques: List[Dict[str, Any]]) -> float:
        """Calculate overall risk score for the incident"""
        base_score = 0.0
        
        # IOC-based scoring
        for ioc in iocs:
            confidence = ioc.get('confidence', 0.5)
            if ioc['type'] in ['sha256_hashes', 'md5_hashes']:
                base_score += confidence * 0.3
            elif ioc['type'] in ['ip_addresses', 'domains']:
                base_score += confidence * 0.2
            else:
                base_score += confidence * 0.1
        
        # ATT&CK technique-based scoring
        for technique in attack_techniques:
            tactic = technique.get('tactic', '')
            if tactic in ['Initial Access', 'Execution', 'Persistence']:
                base_score += 0.4
            elif tactic in ['Defense Evasion', 'Command and Control']:
                base_score += 0.3
            else:
                base_score += 0.2
        
        # Normalize to 0-10 scale
        return min(base_score, 10.0)
    
    async def _generate_recommendations(self, iocs: List[Dict[str, Any]], attack_techniques: List[Dict[str, Any]]) -> List[str]:
        """Generate remediation recommendations"""
        recommendations = []
        
        # IOC-based recommendations
        if any(ioc['type'] in ['ip_addresses', 'domains'] for ioc in iocs):
            recommendations.append("Block identified malicious IP addresses and domains at network perimeter")
        
        if any(ioc['type'] in ['sha256_hashes', 'md5_hashes'] for ioc in iocs):
            recommendations.append("Add malicious file hashes to endpoint protection signatures")
        
        # ATT&CK-based recommendations
        tactics = set(technique.get('tactic') for technique in attack_techniques)
        
        if 'Initial Access' in tactics:
            recommendations.append("Review and strengthen email security controls")
        
        if 'Execution' in tactics:
            recommendations.append("Implement application whitelisting and PowerShell logging")
        
        if 'Command and Control' in tactics:
            recommendations.append("Monitor and restrict outbound network connections")
        
        if not recommendations:
            recommendations.append("Continue monitoring for additional indicators")
        
        return recommendations
    
    async def _enrich_iocs_with_threat_intel(self, iocs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Enrich IOCs with threat intelligence"""
        # TODO: Integrate with threat intelligence feeds
        for ioc in iocs:
            # Simulate threat intel enrichment
            if ioc['type'] in ['ip_addresses', 'domains']:
                ioc['threat_level'] = 'medium'
                ioc['threat_actor'] = 'APT-UNKNOWN'
                ioc['campaign'] = 'Unknown Campaign'
        
        return iocs
    
    async def _store_forensic_results(self, forensic_report: Dict[str, Any]) -> None:
        """Store forensic analysis results"""
        # TODO: Store in database
        logger.info(f"Storing forensic results for incident {forensic_report['incident_id']}")
    
    async def _store_ioc_results(self, incident_id: str, iocs: List[Dict[str, Any]]) -> None:
        """Store IOC results"""
        # TODO: Store in database
        logger.info(f"Storing {len(iocs)} IOCs for incident {incident_id}")
    
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
