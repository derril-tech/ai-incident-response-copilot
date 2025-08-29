import pytest
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, patch

from src.workers.timeline_enhanced import TimelineWorker


class TestTimelineWorker:
    """Test suite for timeline worker"""
    
    @pytest.fixture
    def timeline_worker(self):
        return TimelineWorker()
    
    @pytest.fixture
    def sample_events(self):
        base_time = datetime.utcnow()
        return [
            {
                "id": "evt_1",
                "timestamp": base_time,
                "source": "siem",
                "event_type": "alert",
                "severity": "high",
                "entities": ["host_1", "user_1"],
                "data": {"alert_id": "ALT-001"}
            },
            {
                "id": "evt_2", 
                "timestamp": base_time + timedelta(minutes=5),
                "source": "edr",
                "event_type": "process",
                "severity": "medium",
                "entities": ["host_1", "process_1"],
                "data": {"process_name": "powershell.exe"}
            },
            {
                "id": "evt_3",
                "timestamp": base_time + timedelta(minutes=10),
                "source": "firewall",
                "event_type": "network",
                "severity": "high",
                "entities": ["host_1", "ip_1"],
                "data": {"destination_ip": "192.168.1.100"}
            }
        ]
    
    @pytest.mark.asyncio
    async def test_temporal_correlation(self, timeline_worker, sample_events):
        """Test temporal event correlation"""
        correlated_events = await timeline_worker._correlate_temporal_events(sample_events)
        
        # All events should be in same correlation group (within time window)
        assert len(correlated_events) == 3
        assert all(event.get('correlation_group') == 0 for event in correlated_events)
        assert all(event.get('group_size') == 3 for event in correlated_events)
    
    @pytest.mark.asyncio
    async def test_entity_linking(self, timeline_worker, sample_events):
        """Test entity linking across events"""
        linked_events = await timeline_worker._link_entities(sample_events)
        
        # Events with shared entities should be linked
        host_1_events = [e for e in linked_events if "host_1" in e.get("entities", [])]
        assert len(host_1_events) == 3
        
        # Check entity centrality calculation
        for event in linked_events:
            if "host_1" in event.get("entities", []):
                assert event.get("entity_centrality", 0) > 0
    
    @pytest.mark.asyncio
    async def test_temporal_anomaly_detection(self, timeline_worker):
        """Test temporal anomaly detection"""
        # Create events with large time gap
        base_time = datetime.utcnow()
        events_with_gap = [
            {
                "id": "evt_1",
                "timestamp": base_time,
                "source": "test"
            },
            {
                "id": "evt_2", 
                "timestamp": base_time + timedelta(hours=3),  # 3 hour gap
                "source": "test"
            }
        ]
        
        anomalies = await timeline_worker._detect_temporal_anomalies(events_with_gap)
        
        assert len(anomalies) == 1
        assert anomalies[0]["type"] == "temporal_gap"
        assert "3h gap" in anomalies[0]["description"]
    
    @pytest.mark.asyncio
    async def test_volume_anomaly_detection(self, timeline_worker):
        """Test volume anomaly detection"""
        base_time = datetime.utcnow()
        
        # Create high volume of events in one hour
        high_volume_events = []
        for i in range(20):  # 20 events in same hour
            high_volume_events.append({
                "id": f"evt_{i}",
                "timestamp": base_time + timedelta(minutes=i),
                "source": "test"
            })
        
        # Add normal volume for other hours
        for i in range(3):
            high_volume_events.append({
                "id": f"normal_{i}",
                "timestamp": base_time + timedelta(hours=i+1, minutes=10),
                "source": "test"
            })
        
        anomalies = await timeline_worker._detect_volume_anomalies(high_volume_events)
        
        assert len(anomalies) >= 1
        volume_anomaly = next((a for a in anomalies if a["type"] == "volume_spike"), None)
        assert volume_anomaly is not None
        assert volume_anomaly["severity"] == "high"
    
    @pytest.mark.asyncio
    async def test_entity_anomaly_detection(self, timeline_worker):
        """Test entity-based anomaly detection"""
        # Create events where one entity appears frequently
        hyperactive_events = []
        for i in range(15):  # Entity appears 15 times
            hyperactive_events.append({
                "id": f"evt_{i}",
                "timestamp": datetime.utcnow(),
                "entities": ["hyperactive_entity", f"normal_entity_{i}"]
            })
        
        # Add some normal entities
        for i in range(3):
            hyperactive_events.append({
                "id": f"normal_{i}",
                "timestamp": datetime.utcnow(),
                "entities": [f"normal_only_{i}"]
            })
        
        anomalies = await timeline_worker._detect_entity_anomalies(hyperactive_events)
        
        assert len(anomalies) >= 1
        entity_anomaly = next((a for a in anomalies if a["type"] == "entity_hyperactivity"), None)
        assert entity_anomaly is not None
        assert "hyperactive_entity" in entity_anomaly["entity"]
    
    @pytest.mark.asyncio
    async def test_incident_phase_identification(self, timeline_worker, sample_events):
        """Test incident phase identification"""
        phases = await timeline_worker._identify_incident_phases(sample_events)
        
        assert len(phases) >= 1
        assert phases[0]["name"] == "initial_detection"
        assert "start_time" in phases[0]
        assert "end_time" in phases[0]
        assert "events" in phases[0]
        assert "severity" in phases[0]
    
    @pytest.mark.asyncio
    async def test_timeline_structure_building(self, timeline_worker, sample_events):
        """Test timeline structure building"""
        # Mock anomalies
        anomalies = [
            {
                "type": "test_anomaly",
                "description": "Test anomaly for timeline",
                "severity": "medium"
            }
        ]
        
        timeline = await timeline_worker._build_timeline_structure(
            "INC-001", 
            sample_events, 
            anomalies
        )
        
        assert timeline["incident_id"] == "INC-001"
        assert timeline["total_events"] == len(sample_events)
        assert "phases" in timeline
        assert "anomalies" in timeline
        assert "events" in timeline
        assert "metadata" in timeline
        assert timeline["metadata"]["correlation_algorithm"] == "temporal_clustering"
    
    @pytest.mark.asyncio
    async def test_timeline_summary_generation(self, timeline_worker, sample_events):
        """Test timeline summary generation"""
        timeline = {
            "events": sample_events,
            "phases": [{"name": "test_phase"}],
            "anomalies": [{"type": "test_anomaly"}]
        }
        
        summary = await timeline_worker._generate_timeline_summary(timeline)
        
        assert summary["total_events"] == len(sample_events)
        assert summary["total_phases"] == 1
        assert summary["anomalies_detected"] == 1
        assert "duration" in summary
        assert "severity_distribution" in summary
        assert "key_findings" in summary
    
    def test_severity_distribution_calculation(self, timeline_worker, sample_events):
        """Test severity distribution calculation"""
        distribution = timeline_worker._calculate_severity_distribution(sample_events)
        
        assert "critical" in distribution
        assert "high" in distribution
        assert "medium" in distribution
        assert "low" in distribution
        assert distribution["high"] == 2  # Two high severity events
        assert distribution["medium"] == 1  # One medium severity event
    
    def test_incident_duration_calculation(self, timeline_worker, sample_events):
        """Test incident duration calculation"""
        duration = timeline_worker._calculate_incident_duration(sample_events)
        
        assert isinstance(duration, str)
        assert "h" in duration or "m" in duration
    
    def test_key_findings_extraction(self, timeline_worker, sample_events):
        """Test key findings extraction"""
        anomalies = [
            {"type": "volume_spike", "description": "High event volume"},
            {"type": "temporal_gap", "description": "Time gap detected"}
        ]
        
        findings = timeline_worker._extract_key_findings(sample_events, anomalies)
        
        assert isinstance(findings, list)
        assert len(findings) > 0
        
        # Should detect high severity events
        high_severity_finding = next(
            (f for f in findings if "high/critical severity" in f), 
            None
        )
        assert high_severity_finding is not None


if __name__ == "__main__":
    pytest.main([__file__])
