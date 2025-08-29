import pytest
from datetime import datetime
from unittest.mock import AsyncMock, patch

from src.workers.report_enhanced import ReportWorker


class TestReportWorker:
    """Test suite for report worker"""
    
    @pytest.fixture
    def report_worker(self):
        return ReportWorker()
    
    @pytest.fixture
    def sample_incident_data(self):
        return {
            "incident": {
                "id": "INC-001",
                "title": "Test Incident",
                "severity": "high",
                "status": "investigating"
            },
            "timeline": {
                "events": [
                    {
                        "timestamp": "2023-12-01T10:00:00Z",
                        "type": "alert",
                        "description": "Suspicious activity detected"
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
                "risk_score": 7.5,
                "attack_techniques": [
                    {
                        "id": "T1059",
                        "name": "Command and Scripting Interpreter",
                        "confidence": 0.9
                    }
                ]
            },
            "artifacts": [
                {"id": "art_1", "type": "log_file", "name": "system.log"}
            ],
            "iocs": [
                {"type": "ip_address", "value": "1.2.3.4", "confidence": 0.8}
            ]
        }
    
    def test_agent_initialization(self, report_worker):
        """Test CrewAI agent initialization"""
        agents = report_worker.agents
        
        # Verify all required agents are present
        required_agents = [
            "data_collector", "timeline_analyst", "forensic_analyst",
            "security_writer", "quality_reviewer"
        ]
        
        for agent_name in required_agents:
            assert agent_name in agents
            agent = agents[agent_name]
            assert "role" in agent
            assert "goal" in agent
            assert "backstory" in agent
            assert "capabilities" in agent
    
    def test_task_initialization(self, report_worker):
        """Test CrewAI task initialization"""
        tasks = report_worker.tasks
        
        # Verify all required tasks are present
        required_tasks = [
            "data_collection", "timeline_analysis", "forensic_analysis",
            "executive_summary", "technical_details", "recommendations",
            "lessons_learned", "quality_review"
        ]
        
        for task_name in required_tasks:
            assert task_name in tasks
            task = tasks[task_name]
            assert "description" in task
            assert "expected_output" in task
            assert "agent" in task
    
    @pytest.mark.asyncio
    async def test_data_collection_task(self, report_worker, sample_incident_data):
        """Test data collection task execution"""
        result = await report_worker._execute_data_collection_task(sample_incident_data)
        
        assert "summary" in result
        assert "data_sources" in result
        assert "total_events" in result
        assert "total_artifacts" in result
        assert "total_iocs" in result
        assert "completeness_score" in result
        
        assert result["total_events"] == 1
        assert result["total_artifacts"] == 1
        assert result["total_iocs"] == 1
        assert result["completeness_score"] > 0.9
    
    @pytest.mark.asyncio
    async def test_timeline_analysis_task(self, report_worker, sample_incident_data):
        """Test timeline analysis task execution"""
        result = await report_worker._execute_timeline_analysis_task(sample_incident_data)
        
        assert "incident_duration" in result
        assert "total_phases" in result
        assert "key_phases" in result
        assert "critical_events" in result
        assert "attack_progression" in result
        
        assert result["total_phases"] == 1
        assert len(result["key_phases"]) >= 3  # Should generate standard phases
        assert isinstance(result["critical_events"], list)
    
    @pytest.mark.asyncio
    async def test_forensic_analysis_task(self, report_worker, sample_incident_data):
        """Test forensic analysis task execution"""
        result = await report_worker._execute_forensic_analysis_task(sample_incident_data)
        
        assert "attack_techniques" in result
        assert "ioc_summary" in result
        assert "malware_analysis" in result
        assert "network_analysis" in result
        assert "process_analysis" in result
        assert "risk_score" in result
        
        assert result["risk_score"] == 7.5
        assert result["ioc_summary"]["total_iocs"] == 1
    
    @pytest.mark.asyncio
    async def test_executive_summary_task(self, report_worker, sample_incident_data):
        """Test executive summary task execution"""
        # Mock report sections
        report_sections = {
            "forensic_analysis": {"risk_score": 7.5},
            "timeline_analysis": {"incident_duration": "4 hours"}
        }
        
        result = await report_worker._execute_executive_summary_task(
            sample_incident_data, report_sections
        )
        
        assert "incident_overview" in result
        assert "business_impact" in result
        assert "key_findings" in result
        assert "immediate_actions_taken" in result
        assert "risk_assessment" in result
        
        # Verify business impact structure
        business_impact = result["business_impact"]
        assert "severity" in business_impact
        assert "affected_systems" in business_impact
        assert "estimated_cost" in business_impact
    
    @pytest.mark.asyncio
    async def test_recommendations_task(self, report_worker, sample_incident_data):
        """Test recommendations task execution"""
        report_sections = {}
        result = await report_worker._execute_recommendations_task(
            sample_incident_data, report_sections
        )
        
        assert "immediate_actions" in result
        assert "short_term_improvements" in result
        assert "long_term_strategy" in result
        assert "compliance_actions" in result
        
        # Verify immediate actions structure
        immediate_actions = result["immediate_actions"]
        assert len(immediate_actions) > 0
        
        for action in immediate_actions:
            assert "priority" in action
            assert "action" in action
            assert "timeline" in action
            assert "owner" in action
    
    @pytest.mark.asyncio
    async def test_lessons_learned_task(self, report_worker, sample_incident_data):
        """Test lessons learned task execution"""
        report_sections = {}
        result = await report_worker._execute_lessons_learned_task(
            sample_incident_data, report_sections
        )
        
        assert "what_worked_well" in result
        assert "areas_for_improvement" in result
        assert "process_improvements" in result
        assert "training_needs" in result
        assert "technology_gaps" in result
        
        # Verify process improvements structure
        process_improvements = result["process_improvements"]
        assert len(process_improvements) > 0
        
        for improvement in process_improvements:
            assert "area" in improvement
            assert "improvement" in improvement
            assert "expected_benefit" in improvement
    
    @pytest.mark.asyncio
    async def test_quality_review_task(self, report_worker):
        """Test quality review task execution"""
        # Mock report sections
        report_sections = {
            "executive_summary": {"incident_overview": "Test overview"},
            "technical_details": {"attack_vector": "Test vector"},
            "timeline_analysis": {"incident_duration": "4 hours"},
            "forensic_analysis": {"risk_score": 7.5},
            "recommendations": {"immediate_actions": []},
            "lessons_learned": {"what_worked_well": []}
        }
        
        result = await report_worker._execute_quality_review_task(report_sections)
        
        assert "completeness_check" in result
        assert "accuracy_validation" in result
        assert "quality_score" in result
        assert "review_notes" in result
        assert "final_approval" in result
        assert "reviewer" in result
        assert "review_date" in result
        
        # Verify completeness check
        completeness = result["completeness_check"]
        for section in ["executive_summary", "technical_details", "timeline_analysis"]:
            assert section in completeness
            assert completeness[section] == "Complete"
        
        assert result["quality_score"] > 8.0
        assert result["final_approval"] is True
    
    @pytest.mark.asyncio
    async def test_final_report_compilation(self, report_worker, sample_incident_data):
        """Test final report compilation"""
        # Mock report sections
        report_sections = {
            "executive_summary": {"incident_overview": "Test overview"},
            "timeline_analysis": {"incident_duration": "4 hours"},
            "technical_details": {"attack_vector": "Test vector"},
            "forensic_analysis": {"risk_score": 7.5},
            "recommendations": {"immediate_actions": []},
            "lessons_learned": {"what_worked_well": []},
            "quality_review": {"quality_score": 9.2, "final_approval": True}
        }
        
        final_report = await report_worker._compile_final_report(
            "INC-001", report_sections
        )
        
        assert "incident_id" in final_report
        assert "report_id" in final_report
        assert "title" in final_report
        assert "status" in final_report
        assert "sections" in final_report
        assert "metadata" in final_report
        
        # Verify report structure
        assert final_report["incident_id"] == "INC-001"
        assert final_report["status"] == "final"
        
        # Verify sections
        sections = final_report["sections"]
        required_sections = [
            "executive_summary", "incident_overview", "timeline_analysis",
            "technical_analysis", "forensic_findings", "recommendations",
            "lessons_learned", "appendices"
        ]
        
        for section in required_sections:
            assert section in sections
        
        # Verify metadata
        metadata = final_report["metadata"]
        assert metadata["generator"] == "CrewAI Multi-Agent System"
        assert metadata["quality_score"] == 9.2
    
    @pytest.mark.asyncio
    async def test_draft_report_creation(self, report_worker, sample_incident_data):
        """Test draft report creation"""
        draft_sections = await report_worker._generate_draft_sections(sample_incident_data)
        
        required_sections = ["executive_summary", "timeline", "technical_analysis", "recommendations"]
        
        for section in required_sections:
            assert section in draft_sections
            assert draft_sections[section]["status"] == "draft"
            assert "content" in draft_sections[section]
    
    def test_incident_duration_calculation(self, report_worker):
        """Test incident duration calculation"""
        events = [
            {"timestamp": datetime(2023, 12, 1, 10, 0, 0)},
            {"timestamp": datetime(2023, 12, 1, 14, 30, 0)}
        ]
        
        duration = report_worker._calculate_incident_duration(events)
        assert "4 hours 30 minutes" in duration
    
    def test_critical_events_identification(self, report_worker):
        """Test critical events identification"""
        events = [
            {
                "timestamp": "2023-12-01T10:00:00Z",
                "description": "Initial compromise detected",
                "severity": "high"
            },
            {
                "timestamp": "2023-12-01T10:30:00Z", 
                "description": "Lateral movement observed",
                "severity": "critical"
            }
        ]
        
        critical_events = report_worker._identify_critical_events(events)
        
        assert len(critical_events) == 2
        assert critical_events[0]["severity"] == "high"
        assert critical_events[1]["severity"] == "critical"
    
    @pytest.mark.asyncio
    async def test_crew_workflow_execution(self, report_worker, sample_incident_data):
        """Test complete CrewAI workflow execution"""
        report_sections = await report_worker._execute_crew_workflow(sample_incident_data)
        
        # Verify all sections are generated
        expected_sections = [
            "data_collection", "timeline_analysis", "forensic_analysis",
            "executive_summary", "technical_details", "recommendations",
            "lessons_learned", "quality_review"
        ]
        
        for section in expected_sections:
            assert section in report_sections
            assert isinstance(report_sections[section], dict)
    
    @pytest.mark.asyncio
    async def test_report_generation_end_to_end(self, report_worker):
        """Test end-to-end report generation"""
        incident_id = "INC-TEST-001"
        
        # Mock the data gathering
        with patch.object(report_worker, '_gather_incident_data') as mock_gather:
            mock_gather.return_value = {
                "incident": {"id": incident_id},
                "timeline": {"events": []},
                "forensics": {"risk_score": 5.0},
                "artifacts": [],
                "iocs": []
            }
            
            # Mock the storage
            with patch.object(report_worker, '_store_report') as mock_store:
                result = await report_worker._generate_report(incident_id)
                
                assert result is not None
                assert "incident_id" in result
                assert result["incident_id"] == incident_id
                
                # Verify storage was called
                mock_store.assert_called_once()


if __name__ == "__main__":
    pytest.main([__file__])
