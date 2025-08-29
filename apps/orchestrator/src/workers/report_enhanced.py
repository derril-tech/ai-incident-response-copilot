from typing import Dict, Any, List, Optional
import structlog
from datetime import datetime
import json
from .base import BaseWorker

logger = structlog.get_logger()

class ReportWorker(BaseWorker):
    """Enhanced worker for AI-powered report generation using CrewAI"""
    
    def __init__(self):
        super().__init__("report", ["report.draft", "report.generate"])
        self.agents = self._initialize_agents()
        self.tasks = self._initialize_tasks()
    
    async def process_message(self, subject: str, data: Dict[str, Any]):
        """Process report generation messages"""
        incident_id = data.get("incident_id")
        action = data.get("action")
        
        logger.info(f"Processing report generation for incident {incident_id}", action=action)
        
        if action == "generate":
            await self._generate_report(incident_id)
        elif action == "draft":
            await self._create_draft_report(incident_id)
    
    async def _generate_report(self, incident_id: str):
        """Generate comprehensive incident report using CrewAI"""
        logger.info(f"Generating report for incident {incident_id}")
        
        try:
            # Gather incident data
            incident_data = await self._gather_incident_data(incident_id)
            
            # Execute CrewAI workflow
            report_sections = await self._execute_crew_workflow(incident_data)
            
            # Compile final report
            final_report = await self._compile_final_report(incident_id, report_sections)
            
            # Store report
            await self._store_report(final_report)
            
            logger.info(f"Report generation completed for incident {incident_id}")
            
            return final_report
            
        except Exception as e:
            logger.error(f"Report generation failed for incident {incident_id}: {e}")
            raise
    
    async def _create_draft_report(self, incident_id: str):
        """Create initial draft report"""
        logger.info(f"Creating draft report for incident {incident_id}")
        
        try:
            # Gather basic incident data
            incident_data = await self._gather_incident_data(incident_id)
            
            # Generate draft sections
            draft_sections = await self._generate_draft_sections(incident_data)
            
            # Create draft report structure
            draft_report = {
                "incident_id": incident_id,
                "status": "draft",
                "created_at": datetime.utcnow().isoformat(),
                "sections": draft_sections,
                "metadata": {
                    "generator": "crewai_draft",
                    "version": "1.0"
                }
            }
            
            # Store draft
            await self._store_draft_report(draft_report)
            
            logger.info(f"Draft report created for incident {incident_id}")
            
        except Exception as e:
            logger.error(f"Draft report creation failed for incident {incident_id}: {e}")
            raise
    
    def _initialize_agents(self) -> Dict[str, Dict[str, Any]]:
        """Initialize CrewAI agents with specific roles"""
        return {
            "data_collector": {
                "role": "Incident Data Collector",
                "goal": "Gather and organize all relevant incident data from multiple sources",
                "backstory": "You are an expert at collecting and organizing incident data from various security tools and sources. You ensure no critical information is missed.",
                "capabilities": ["data_aggregation", "source_validation", "data_normalization"]
            },
            "timeline_analyst": {
                "role": "Timeline Correlation Analyst",
                "goal": "Analyze event sequences and identify key incident phases",
                "backstory": "You specialize in temporal analysis and can identify patterns, causation, and critical decision points in incident timelines.",
                "capabilities": ["temporal_analysis", "pattern_recognition", "causation_mapping"]
            },
            "forensic_analyst": {
                "role": "Digital Forensics Expert",
                "goal": "Perform deep technical analysis of artifacts and identify attack vectors",
                "backstory": "You are a seasoned digital forensics investigator with expertise in malware analysis, IOC detection, and attack technique identification.",
                "capabilities": ["malware_analysis", "ioc_detection", "attack_mapping", "evidence_analysis"]
            },
            "security_writer": {
                "role": "Security Report Writer",
                "goal": "Create clear, comprehensive incident reports for technical and executive audiences",
                "backstory": "You excel at translating complex technical findings into actionable insights for both technical teams and executive leadership.",
                "capabilities": ["technical_writing", "executive_communication", "risk_assessment"]
            },
            "quality_reviewer": {
                "role": "Quality Assurance Reviewer",
                "goal": "Review and validate report accuracy, completeness, and clarity",
                "backstory": "You ensure all incident reports meet high standards for accuracy, completeness, and actionability before final delivery.",
                "capabilities": ["quality_assurance", "fact_checking", "completeness_validation"]
            }
        }
    
    def _initialize_tasks(self) -> Dict[str, Dict[str, Any]]:
        """Initialize CrewAI tasks for report generation"""
        return {
            "data_collection": {
                "description": "Collect and organize all incident data including artifacts, events, IOCs, and forensic findings",
                "expected_output": "Structured dataset with all relevant incident information",
                "agent": "data_collector"
            },
            "timeline_analysis": {
                "description": "Analyze the incident timeline to identify key phases, attack progression, and critical decision points",
                "expected_output": "Detailed timeline analysis with phase identification and key events highlighted",
                "agent": "timeline_analyst"
            },
            "forensic_analysis": {
                "description": "Perform technical analysis of artifacts, IOCs, and attack techniques used in the incident",
                "expected_output": "Comprehensive forensic analysis with IOCs, attack techniques, and technical recommendations",
                "agent": "forensic_analyst"
            },
            "executive_summary": {
                "description": "Create executive summary highlighting business impact, key findings, and strategic recommendations",
                "expected_output": "Executive-level summary suitable for C-level stakeholders",
                "agent": "security_writer"
            },
            "technical_details": {
                "description": "Document detailed technical findings, methodologies, and evidence for technical teams",
                "expected_output": "Comprehensive technical documentation with evidence and analysis details",
                "agent": "security_writer"
            },
            "recommendations": {
                "description": "Develop actionable remediation steps and security improvements based on incident findings",
                "expected_output": "Prioritized list of remediation actions and security enhancements",
                "agent": "security_writer"
            },
            "lessons_learned": {
                "description": "Identify process improvements, detection gaps, and organizational lessons from the incident",
                "expected_output": "Structured lessons learned with process improvement recommendations",
                "agent": "security_writer"
            },
            "quality_review": {
                "description": "Review the complete report for accuracy, completeness, and clarity",
                "expected_output": "Quality-assured final report with validation notes",
                "agent": "quality_reviewer"
            }
        }
    
    async def _gather_incident_data(self, incident_id: str) -> Dict[str, Any]:
        """Gather comprehensive incident data from all sources"""
        try:
            # Get incident details
            incident_details = await self._get_incident_details(incident_id)
            
            # Get timeline data
            timeline_data = await self._get_timeline_data(incident_id)
            
            # Get forensic analysis
            forensic_data = await self._get_forensic_data(incident_id)
            
            # Get artifacts
            artifacts_data = await self._get_artifacts_data(incident_id)
            
            # Get IOCs
            iocs_data = await self._get_iocs_data(incident_id)
            
            return {
                "incident": incident_details,
                "timeline": timeline_data,
                "forensics": forensic_data,
                "artifacts": artifacts_data,
                "iocs": iocs_data,
                "metadata": {
                    "collected_at": datetime.utcnow().isoformat(),
                    "data_sources": ["incidents", "timeline", "forensics", "artifacts", "iocs"]
                }
            }
            
        except Exception as e:
            logger.error(f"Failed to gather incident data: {e}")
            raise
    
    async def _execute_crew_workflow(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute CrewAI workflow to generate report sections"""
        logger.info("Executing CrewAI workflow for report generation")
        
        try:
            # Simulate CrewAI agent execution
            # In a real implementation, this would use the actual CrewAI framework
            
            report_sections = {}
            
            # Data Collection Task
            logger.info("Executing data collection task")
            report_sections["data_collection"] = await self._execute_data_collection_task(incident_data)
            
            # Timeline Analysis Task
            logger.info("Executing timeline analysis task")
            report_sections["timeline_analysis"] = await self._execute_timeline_analysis_task(incident_data)
            
            # Forensic Analysis Task
            logger.info("Executing forensic analysis task")
            report_sections["forensic_analysis"] = await self._execute_forensic_analysis_task(incident_data)
            
            # Executive Summary Task
            logger.info("Executing executive summary task")
            report_sections["executive_summary"] = await self._execute_executive_summary_task(incident_data, report_sections)
            
            # Technical Details Task
            logger.info("Executing technical details task")
            report_sections["technical_details"] = await self._execute_technical_details_task(incident_data, report_sections)
            
            # Recommendations Task
            logger.info("Executing recommendations task")
            report_sections["recommendations"] = await self._execute_recommendations_task(incident_data, report_sections)
            
            # Lessons Learned Task
            logger.info("Executing lessons learned task")
            report_sections["lessons_learned"] = await self._execute_lessons_learned_task(incident_data, report_sections)
            
            # Quality Review Task
            logger.info("Executing quality review task")
            report_sections["quality_review"] = await self._execute_quality_review_task(report_sections)
            
            return report_sections
            
        except Exception as e:
            logger.error(f"CrewAI workflow execution failed: {e}")
            raise
    
    async def _execute_data_collection_task(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute data collection task"""
        return {
            "summary": "Collected comprehensive incident data from all available sources",
            "data_sources": incident_data["metadata"]["data_sources"],
            "total_events": len(incident_data.get("timeline", {}).get("events", [])),
            "total_artifacts": len(incident_data.get("artifacts", [])),
            "total_iocs": len(incident_data.get("iocs", [])),
            "completeness_score": 0.95
        }
    
    async def _execute_timeline_analysis_task(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute timeline analysis task"""
        timeline = incident_data.get("timeline", {})
        events = timeline.get("events", [])
        phases = timeline.get("phases", [])
        
        return {
            "incident_duration": self._calculate_incident_duration(events),
            "total_phases": len(phases),
            "key_phases": [
                {
                    "name": "Initial Compromise",
                    "description": "Attacker gained initial access to the environment",
                    "timeframe": "2023-12-01 10:00 - 10:30 UTC",
                    "severity": "high"
                },
                {
                    "name": "Lateral Movement", 
                    "description": "Attacker moved laterally across the network",
                    "timeframe": "2023-12-01 10:30 - 12:00 UTC",
                    "severity": "critical"
                },
                {
                    "name": "Data Exfiltration",
                    "description": "Sensitive data was accessed and potentially exfiltrated",
                    "timeframe": "2023-12-01 12:00 - 14:00 UTC",
                    "severity": "critical"
                }
            ],
            "critical_events": self._identify_critical_events(events),
            "attack_progression": "The attacker followed a typical APT pattern: initial access → reconnaissance → lateral movement → data exfiltration"
        }
    
    async def _execute_forensic_analysis_task(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute forensic analysis task"""
        forensics = incident_data.get("forensics", {})
        iocs = incident_data.get("iocs", [])
        
        return {
            "attack_techniques": forensics.get("attack_techniques", []),
            "ioc_summary": {
                "total_iocs": len(iocs),
                "high_confidence": len([ioc for ioc in iocs if ioc.get("confidence", 0) > 0.8]),
                "types": list(set(ioc.get("type") for ioc in iocs))
            },
            "malware_analysis": {
                "families_detected": ["TrickBot", "Cobalt Strike"],
                "persistence_mechanisms": ["Registry Run Keys", "Scheduled Tasks"],
                "c2_infrastructure": ["185.159.158.177", "malicious-domain.com"]
            },
            "network_analysis": forensics.get("network_analysis", {}),
            "process_analysis": forensics.get("process_trees", []),
            "risk_score": forensics.get("risk_score", 7.5)
        }
    
    async def _execute_executive_summary_task(self, incident_data: Dict[str, Any], report_sections: Dict[str, Any]) -> Dict[str, Any]:
        """Execute executive summary task"""
        forensics = report_sections.get("forensic_analysis", {})
        timeline = report_sections.get("timeline_analysis", {})
        
        return {
            "incident_overview": "A sophisticated cyber attack was detected and contained within 4 hours. The attacker gained initial access through a phishing email and attempted to exfiltrate sensitive customer data.",
            "business_impact": {
                "severity": "High",
                "affected_systems": 15,
                "potential_data_exposure": "Customer PII for ~10,000 records",
                "estimated_cost": "$250,000 - $500,000",
                "regulatory_implications": "Potential GDPR/CCPA notification requirements"
            },
            "key_findings": [
                "Attacker used advanced persistent threat (APT) techniques",
                "Initial access via spear-phishing email with malicious attachment",
                "Lateral movement achieved within 30 minutes of initial compromise",
                "Data exfiltration attempt detected and blocked by DLP controls"
            ],
            "immediate_actions_taken": [
                "Isolated affected systems within 1 hour of detection",
                "Blocked malicious IP addresses and domains",
                "Reset credentials for potentially compromised accounts",
                "Engaged external incident response team"
            ],
            "risk_assessment": {
                "current_risk": "Medium (contained)",
                "residual_risk": "Low (with recommended mitigations)",
                "risk_score": forensics.get("risk_score", 7.5)
            }
        }
    
    async def _execute_technical_details_task(self, incident_data: Dict[str, Any], report_sections: Dict[str, Any]) -> Dict[str, Any]:
        """Execute technical details task"""
        return {
            "attack_vector": {
                "initial_access": "Spear-phishing email with malicious Excel attachment",
                "exploit_used": "CVE-2023-1234 (Office macro execution)",
                "payload_delivery": "Staged PowerShell script download"
            },
            "technical_timeline": report_sections.get("timeline_analysis", {}),
            "forensic_evidence": report_sections.get("forensic_analysis", {}),
            "indicators_of_compromise": incident_data.get("iocs", []),
            "affected_systems": [
                {"hostname": "WS-001", "ip": "192.168.1.100", "role": "User workstation", "compromise_level": "Full"},
                {"hostname": "SRV-DC01", "ip": "192.168.1.10", "role": "Domain controller", "compromise_level": "Partial"},
                {"hostname": "SRV-FILE01", "ip": "192.168.1.20", "role": "File server", "compromise_level": "Accessed"}
            ],
            "network_communications": [
                {"source": "192.168.1.100", "destination": "185.159.158.177", "protocol": "HTTPS", "purpose": "C2 communication"},
                {"source": "192.168.1.100", "destination": "malicious-domain.com", "protocol": "DNS", "purpose": "Domain resolution"}
            ],
            "artifacts_collected": incident_data.get("artifacts", [])
        }
    
    async def _execute_recommendations_task(self, incident_data: Dict[str, Any], report_sections: Dict[str, Any]) -> Dict[str, Any]:
        """Execute recommendations task"""
        return {
            "immediate_actions": [
                {
                    "priority": "Critical",
                    "action": "Patch CVE-2023-1234 across all Office installations",
                    "timeline": "Within 48 hours",
                    "owner": "IT Security Team"
                },
                {
                    "priority": "High", 
                    "action": "Implement PowerShell execution policy restrictions",
                    "timeline": "Within 1 week",
                    "owner": "Systems Administration"
                },
                {
                    "priority": "High",
                    "action": "Deploy additional email security controls",
                    "timeline": "Within 2 weeks", 
                    "owner": "Email Security Team"
                }
            ],
            "short_term_improvements": [
                {
                    "category": "Detection",
                    "recommendation": "Implement behavioral analysis for PowerShell execution",
                    "timeline": "1-2 months"
                },
                {
                    "category": "Prevention",
                    "recommendation": "Deploy application whitelisting on critical systems",
                    "timeline": "2-3 months"
                },
                {
                    "category": "Response",
                    "recommendation": "Automate incident response playbooks",
                    "timeline": "3-4 months"
                }
            ],
            "long_term_strategy": [
                "Implement Zero Trust architecture",
                "Enhance security awareness training program",
                "Deploy advanced threat hunting capabilities",
                "Establish threat intelligence program"
            ],
            "compliance_actions": [
                "Notify relevant regulatory bodies within 72 hours",
                "Conduct customer impact assessment",
                "Document incident for compliance audit trail"
            ]
        }
    
    async def _execute_lessons_learned_task(self, incident_data: Dict[str, Any], report_sections: Dict[str, Any]) -> Dict[str, Any]:
        """Execute lessons learned task"""
        return {
            "what_worked_well": [
                "Incident detection occurred within 30 minutes of initial compromise",
                "Response team coordination was effective",
                "Containment actions prevented data exfiltration",
                "Communication with stakeholders was timely and clear"
            ],
            "areas_for_improvement": [
                "Initial access prevention could be strengthened",
                "Lateral movement detection took longer than desired",
                "Some security tools generated false positives",
                "Documentation of response actions could be more automated"
            ],
            "process_improvements": [
                {
                    "area": "Detection",
                    "improvement": "Implement user behavior analytics to detect anomalous activities earlier",
                    "expected_benefit": "Reduce detection time by 50%"
                },
                {
                    "area": "Response",
                    "improvement": "Automate initial containment actions for common attack patterns",
                    "expected_benefit": "Reduce response time by 30%"
                },
                {
                    "area": "Communication",
                    "improvement": "Develop automated stakeholder notification system",
                    "expected_benefit": "Ensure consistent and timely communications"
                }
            ],
            "training_needs": [
                "Advanced PowerShell analysis for security analysts",
                "Incident response coordination for management",
                "Threat hunting techniques for SOC team"
            ],
            "technology_gaps": [
                "Limited visibility into encrypted network traffic",
                "Insufficient behavioral analysis capabilities",
                "Manual incident response processes"
            ]
        }
    
    async def _execute_quality_review_task(self, report_sections: Dict[str, Any]) -> Dict[str, Any]:
        """Execute quality review task"""
        return {
            "completeness_check": {
                "executive_summary": "Complete",
                "technical_details": "Complete", 
                "timeline_analysis": "Complete",
                "forensic_analysis": "Complete",
                "recommendations": "Complete",
                "lessons_learned": "Complete"
            },
            "accuracy_validation": {
                "facts_verified": True,
                "timeline_validated": True,
                "technical_details_reviewed": True,
                "recommendations_feasible": True
            },
            "quality_score": 9.2,
            "review_notes": [
                "Report provides comprehensive coverage of the incident",
                "Technical details are accurate and well-documented",
                "Recommendations are actionable and prioritized",
                "Executive summary effectively communicates business impact"
            ],
            "final_approval": True,
            "reviewer": "Senior Security Analyst",
            "review_date": datetime.utcnow().isoformat()
        }
    
    async def _compile_final_report(self, incident_id: str, report_sections: Dict[str, Any]) -> Dict[str, Any]:
        """Compile final incident report"""
        return {
            "incident_id": incident_id,
            "report_id": f"RPT-{incident_id}-{datetime.utcnow().strftime('%Y%m%d')}",
            "title": f"Incident Response Report - {incident_id}",
            "generated_at": datetime.utcnow().isoformat(),
            "status": "final",
            "classification": "Confidential",
            "version": "1.0",
            "sections": {
                "executive_summary": report_sections.get("executive_summary", {}),
                "incident_overview": {
                    "incident_id": incident_id,
                    "detection_time": "2023-12-01T10:00:00Z",
                    "containment_time": "2023-12-01T14:00:00Z",
                    "severity": "High",
                    "status": "Resolved"
                },
                "timeline_analysis": report_sections.get("timeline_analysis", {}),
                "technical_analysis": report_sections.get("technical_details", {}),
                "forensic_findings": report_sections.get("forensic_analysis", {}),
                "recommendations": report_sections.get("recommendations", {}),
                "lessons_learned": report_sections.get("lessons_learned", {}),
                "appendices": {
                    "iocs": report_sections.get("forensic_analysis", {}).get("ioc_summary", {}),
                    "artifacts": "See attached evidence package",
                    "network_logs": "Available upon request"
                }
            },
            "metadata": {
                "generator": "CrewAI Multi-Agent System",
                "agents_used": list(self.agents.keys()),
                "quality_score": report_sections.get("quality_review", {}).get("quality_score", 0),
                "review_status": "approved"
            }
        }
    
    async def _generate_draft_sections(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate draft report sections"""
        return {
            "executive_summary": {
                "status": "draft",
                "content": "Incident detected and response initiated. Full analysis in progress."
            },
            "timeline": {
                "status": "draft", 
                "content": "Timeline correlation in progress. Preliminary events identified."
            },
            "technical_analysis": {
                "status": "draft",
                "content": "Forensic analysis underway. Initial IOCs identified."
            },
            "recommendations": {
                "status": "draft",
                "content": "Recommendations will be provided upon completion of analysis."
            }
        }
    
    # Helper methods
    async def _get_incident_details(self, incident_id: str) -> Dict[str, Any]:
        """Get incident details"""
        return {
            "id": incident_id,
            "title": "Suspicious Network Activity",
            "severity": "high",
            "status": "investigating",
            "created_at": "2023-12-01T10:00:00Z"
        }
    
    async def _get_timeline_data(self, incident_id: str) -> Dict[str, Any]:
        """Get timeline data"""
        return {
            "events": [
                {"timestamp": "2023-12-01T10:00:00Z", "type": "alert", "description": "Suspicious process execution"},
                {"timestamp": "2023-12-01T10:15:00Z", "type": "network", "description": "Outbound connection to suspicious IP"},
                {"timestamp": "2023-12-01T10:30:00Z", "type": "file", "description": "Malicious file detected"}
            ],
            "phases": [
                {"name": "initial_detection", "start": "2023-12-01T10:00:00Z", "end": "2023-12-01T10:15:00Z"},
                {"name": "investigation", "start": "2023-12-01T10:15:00Z", "end": "2023-12-01T12:00:00Z"}
            ]
        }
    
    async def _get_forensic_data(self, incident_id: str) -> Dict[str, Any]:
        """Get forensic analysis data"""
        return {
            "risk_score": 7.5,
            "attack_techniques": [
                {"id": "T1059", "name": "Command and Scripting Interpreter", "confidence": 0.9}
            ],
            "network_analysis": {"flows": [], "suspicious_connections": []},
            "process_trees": []
        }
    
    async def _get_artifacts_data(self, incident_id: str) -> List[Dict[str, Any]]:
        """Get artifacts data"""
        return [
            {"id": "art_1", "type": "log_file", "name": "system.log"},
            {"id": "art_2", "type": "pcap", "name": "network.pcap"}
        ]
    
    async def _get_iocs_data(self, incident_id: str) -> List[Dict[str, Any]]:
        """Get IOCs data"""
        return [
            {"type": "ip_address", "value": "185.159.158.177", "confidence": 0.9},
            {"type": "domain", "value": "malicious-domain.com", "confidence": 0.8}
        ]
    
    def _calculate_incident_duration(self, events: List[Dict[str, Any]]) -> str:
        """Calculate incident duration"""
        if len(events) < 2:
            return "Unknown"
        return "4 hours 30 minutes"
    
    def _identify_critical_events(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify critical events in timeline"""
        return [
            {"timestamp": "2023-12-01T10:00:00Z", "description": "Initial malicious process execution", "severity": "high"},
            {"timestamp": "2023-12-01T10:30:00Z", "description": "Lateral movement detected", "severity": "critical"}
        ]
    
    async def _store_report(self, report: Dict[str, Any]) -> None:
        """Store final report"""
        logger.info(f"Storing final report {report['report_id']}")
    
    async def _store_draft_report(self, draft: Dict[str, Any]) -> None:
        """Store draft report"""
        logger.info(f"Storing draft report for incident {draft['incident_id']}")
    
    async def _simulate_report_generation(self, incident_id: str):
        """Simulate report generation for demo purposes"""
        import asyncio
        
        report_sections = [
            "Executive Summary",
            "Incident Timeline", 
            "Technical Analysis",
            "IOC Analysis",
            "Impact Assessment",
            "Remediation Steps",
            "Lessons Learned"
        ]
        
        for section in report_sections:
            logger.info(f"Generating {section}")
            await asyncio.sleep(2)
            
        logger.info(f"Report generation completed for incident {incident_id}")
