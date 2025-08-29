import pytest
from datetime import datetime
from unittest.mock import AsyncMock, patch

from src.workers.forensic_enhanced import ForensicWorker


class TestForensicWorker:
    """Test suite for forensic worker"""
    
    @pytest.fixture
    def forensic_worker(self):
        return ForensicWorker()
    
    @pytest.fixture
    def sample_artifacts(self):
        return [
            {
                "id": "art_1",
                "type": "log_file",
                "content": "powershell.exe -enc base64command 192.168.1.100 malicious-domain.com",
                "hash": "abc123def456"
            },
            {
                "id": "art_2", 
                "type": "pcap",
                "content": "network traffic to 185.159.158.177 on port 443",
                "hash": "def456ghi789"
            }
        ]
    
    @pytest.fixture
    def sample_events(self):
        return [
            {
                "id": "evt_1",
                "timestamp": datetime.utcnow(),
                "type": "process_creation",
                "data": {
                    "process_name": "powershell.exe",
                    "command_line": "powershell -enc malicious_command",
                    "parent_process": "explorer.exe"
                }
            },
            {
                "id": "evt_2",
                "timestamp": datetime.utcnow(),
                "type": "network_connection",
                "data": {
                    "destination_ip": "185.159.158.177",
                    "destination_port": "443",
                    "protocol": "https"
                }
            }
        ]
    
    def test_ioc_pattern_loading(self, forensic_worker):
        """Test IOC pattern loading"""
        patterns = forensic_worker.ioc_patterns
        
        assert "ip_addresses" in patterns
        assert "domains" in patterns
        assert "sha256_hashes" in patterns
        assert "md5_hashes" in patterns
        assert "urls" in patterns
        assert "email_addresses" in patterns
    
    def test_attack_technique_loading(self, forensic_worker):
        """Test ATT&CK technique loading"""
        techniques = forensic_worker.attack_techniques
        
        assert "T1055" in techniques  # Process Injection
        assert "T1059" in techniques  # Command and Scripting Interpreter
        assert "T1071" in techniques  # Application Layer Protocol
        
        # Verify technique structure
        t1059 = techniques["T1059"]
        assert t1059["name"] == "Command and Scripting Interpreter"
        assert t1059["tactic"] == "Execution"
        assert "powershell" in t1059["indicators"]
    
    @pytest.mark.asyncio
    async def test_ioc_detection_ip_addresses(self, forensic_worker, sample_artifacts):
        """Test IP address IOC detection"""
        iocs = await forensic_worker._detect_iocs(sample_artifacts, [])
        
        ip_iocs = [ioc for ioc in iocs if ioc["type"] == "ip_addresses"]
        assert len(ip_iocs) >= 2
        
        # Check for specific IPs
        ip_values = [ioc["value"] for ioc in ip_iocs]
        assert "192.168.1.100" in ip_values
        assert "185.159.158.177" in ip_values
    
    @pytest.mark.asyncio
    async def test_ioc_detection_domains(self, forensic_worker, sample_artifacts):
        """Test domain IOC detection"""
        iocs = await forensic_worker._detect_iocs(sample_artifacts, [])
        
        domain_iocs = [ioc for ioc in iocs if ioc["type"] == "domains"]
        assert len(domain_iocs) >= 1
        
        domain_values = [ioc["value"] for ioc in domain_iocs]
        assert "malicious-domain.com" in domain_values
    
    @pytest.mark.asyncio
    async def test_ioc_confidence_scoring(self, forensic_worker):
        """Test IOC confidence scoring"""
        # Test different IOC types
        sha256_confidence = forensic_worker._calculate_ioc_confidence("sha256_hashes", "abc123")
        ip_confidence = forensic_worker._calculate_ioc_confidence("ip_addresses", "192.168.1.1")
        domain_confidence = forensic_worker._calculate_ioc_confidence("domains", "malicious-temp.com")
        
        # SHA256 should have highest confidence
        assert sha256_confidence > ip_confidence
        assert sha256_confidence == 0.9
        
        # Domain with suspicious keywords should get bonus
        assert domain_confidence > forensic_worker._calculate_ioc_confidence("domains", "google.com")
    
    @pytest.mark.asyncio
    async def test_attack_technique_mapping(self, forensic_worker, sample_events):
        """Test ATT&CK technique mapping"""
        iocs = []  # Empty for this test
        techniques = await forensic_worker._map_attack_techniques(sample_events, iocs)
        
        # Should detect PowerShell execution (T1059)
        powershell_techniques = [t for t in techniques if t["technique_id"] == "T1059"]
        assert len(powershell_techniques) >= 1
        
        technique = powershell_techniques[0]
        assert technique["technique_name"] == "Command and Scripting Interpreter"
        assert technique["tactic"] == "Execution"
        assert technique["evidence"]["indicator"] == "powershell"
    
    @pytest.mark.asyncio
    async def test_process_tree_reconstruction(self, forensic_worker, sample_events):
        """Test process tree reconstruction"""
        process_trees = await forensic_worker._reconstruct_process_trees(sample_events)
        
        # Should have at least one process tree
        assert len(process_trees) >= 1
        
        # Check process structure
        process = process_trees[0]
        assert process["name"] == "powershell.exe"
        assert process["parent"] == "explorer.exe"
        assert "command_line" in process
        assert "timestamp" in process
    
    @pytest.mark.asyncio
    async def test_network_flow_analysis(self, forensic_worker, sample_artifacts):
        """Test network flow analysis"""
        events = []  # Empty for this test
        network_analysis = await forensic_worker._analyze_network_flows(sample_artifacts, events)
        
        assert "flows" in network_analysis
        assert "unique_destinations" in network_analysis
        assert "suspicious_connections" in network_analysis
        
        flows = network_analysis["flows"]
        assert len(flows) >= 2  # Should detect IPs and domains
        
        # Check for IP connection
        ip_flows = [f for f in flows if f["type"] == "ip_connection"]
        assert len(ip_flows) >= 1
        
        # Check for DNS query
        dns_flows = [f for f in flows if f["type"] == "dns_query"]
        assert len(dns_flows) >= 1
    
    def test_suspicious_connection_detection(self, forensic_worker):
        """Test suspicious connection detection"""
        # Test suspicious domain
        suspicious_flow = {
            "destination": "malicious-temp-domain.com",
            "type": "dns_query"
        }
        assert forensic_worker._is_suspicious_connection(suspicious_flow) is True
        
        # Test normal domain
        normal_flow = {
            "destination": "google.com",
            "type": "dns_query"
        }
        assert forensic_worker._is_suspicious_connection(normal_flow) is False
    
    @pytest.mark.asyncio
    async def test_behavioral_pattern_analysis(self, forensic_worker, sample_events):
        """Test behavioral pattern analysis"""
        # Add more process events to trigger rapid creation detection
        extended_events = sample_events.copy()
        for i in range(8):  # Add 8 more process events
            extended_events.append({
                "id": f"evt_proc_{i}",
                "timestamp": datetime.utcnow(),
                "type": "process_creation",
                "data": {"process_name": f"process_{i}.exe"}
            })
        
        patterns = await forensic_worker._analyze_behavioral_patterns(extended_events)
        
        # Should detect rapid process creation
        rapid_creation = next(
            (p for p in patterns if p["pattern"] == "rapid_process_creation"), 
            None
        )
        assert rapid_creation is not None
        assert rapid_creation["severity"] == "medium"
        
        # Should detect PowerShell execution
        powershell_pattern = next(
            (p for p in patterns if p["pattern"] == "powershell_execution"),
            None
        )
        assert powershell_pattern is not None
        assert powershell_pattern["severity"] == "high"
    
    @pytest.mark.asyncio
    async def test_risk_score_calculation(self, forensic_worker):
        """Test risk score calculation"""
        # High-risk IOCs
        high_risk_iocs = [
            {"type": "sha256_hashes", "confidence": 0.9},
            {"type": "ip_addresses", "confidence": 0.8},
            {"type": "domains", "confidence": 0.7}
        ]
        
        # High-risk techniques
        high_risk_techniques = [
            {"tactic": "Initial Access"},
            {"tactic": "Execution"},
            {"tactic": "Command and Control"}
        ]
        
        risk_score = await forensic_worker._calculate_risk_score(high_risk_iocs, high_risk_techniques)
        
        assert isinstance(risk_score, float)
        assert 0 <= risk_score <= 10
        assert risk_score > 1.0  # Should be elevated due to high-risk indicators
    
    @pytest.mark.asyncio
    async def test_recommendation_generation(self, forensic_worker):
        """Test recommendation generation"""
        iocs = [
            {"type": "ip_addresses", "value": "1.2.3.4"},
            {"type": "sha256_hashes", "value": "abc123"}
        ]
        
        techniques = [
            {"tactic": "Initial Access"},
            {"tactic": "Execution"}
        ]
        
        recommendations = await forensic_worker._generate_recommendations(iocs, techniques)
        
        assert isinstance(recommendations, list)
        assert len(recommendations) > 0
        
        # Should recommend blocking IPs/domains
        block_recommendation = next(
            (r for r in recommendations if "Block" in r and "IP" in r),
            None
        )
        assert block_recommendation is not None
        
        # Should recommend adding hashes to signatures
        hash_recommendation = next(
            (r for r in recommendations if "hash" in r and "signatures" in r),
            None
        )
        assert hash_recommendation is not None
    
    @pytest.mark.asyncio
    async def test_memory_artifact_analysis(self, forensic_worker):
        """Test memory artifact analysis"""
        memory_artifacts = [
            {
                "id": "mem_1",
                "type": "memory_dump",
                "content": "powershell.exe process found in memory with suspicious indicators"
            }
        ]
        
        analysis = await forensic_worker._analyze_memory_artifacts(memory_artifacts)
        
        assert "total_dumps" in analysis
        assert "suspicious_processes" in analysis
        assert analysis["total_dumps"] == 1
        
        # Should detect suspicious PowerShell process
        if analysis["suspicious_processes"]:
            process = analysis["suspicious_processes"][0]
            assert process["process"] == "powershell.exe"
            assert "suspicious_indicators" in process
    
    @pytest.mark.asyncio
    async def test_disk_artifact_analysis(self, forensic_worker):
        """Test disk artifact analysis"""
        disk_artifacts = [
            {
                "id": "disk_1",
                "type": "disk_image",
                "content": "disk image containing suspicious files"
            }
        ]
        
        analysis = await forensic_worker._analyze_disk_artifacts(disk_artifacts)
        
        assert "total_images" in analysis
        assert "suspicious_files" in analysis
        assert "persistence_mechanisms" in analysis
        assert "deleted_files" in analysis
        assert analysis["total_images"] == 1
    
    @pytest.mark.asyncio
    async def test_ioc_enrichment(self, forensic_worker):
        """Test IOC enrichment with threat intelligence"""
        iocs = [
            {
                "type": "ip_addresses",
                "value": "1.2.3.4",
                "confidence": 0.8
            },
            {
                "type": "domains",
                "value": "malicious.com",
                "confidence": 0.7
            }
        ]
        
        enriched_iocs = await forensic_worker._enrich_iocs_with_threat_intel(iocs)
        
        # Should add threat intelligence fields
        for ioc in enriched_iocs:
            if ioc["type"] in ["ip_addresses", "domains"]:
                assert "threat_level" in ioc
                assert "threat_actor" in ioc
                assert "campaign" in ioc


if __name__ == "__main__":
    pytest.main([__file__])
