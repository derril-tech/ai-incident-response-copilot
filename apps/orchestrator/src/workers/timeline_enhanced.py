from typing import Dict, Any, List, Optional
import structlog
from datetime import datetime, timedelta
import json
from .base import BaseWorker

logger = structlog.get_logger()

class TimelineWorker(BaseWorker):
    """Enhanced worker for timeline correlation and analysis"""
    
    def __init__(self):
        super().__init__("timeline", ["timeline.build", "timeline.correlate"])
    
    async def process_message(self, subject: str, data: Dict[str, Any]):
        """Process timeline messages"""
        incident_id = data.get("incident_id")
        action = data.get("action")
        
        logger.info(f"Processing timeline for incident {incident_id}", action=action)
        
        if action == "correlate":
            await self._correlate_events(incident_id)
        elif action == "build":
            await self._build_timeline(incident_id)
    
    async def _correlate_events(self, incident_id: str):
        """Correlate events into a timeline"""
        logger.info(f"Correlating events for incident {incident_id}")
        
        try:
            # Fetch raw events from multiple sources
            events = await self._fetch_incident_events(incident_id)
            logger.info(f"Fetched {len(events)} events for correlation")
            
            # Apply temporal correlation
            correlated_events = await self._correlate_temporal_events(events)
            logger.info(f"Correlated into {len(correlated_events)} event clusters")
            
            # Perform entity linking
            linked_events = await self._link_entities(correlated_events)
            logger.info(f"Linked entities across {len(linked_events)} events")
            
            # Detect anomalies
            anomalies = await self._detect_anomalies(linked_events)
            logger.info(f"Detected {len(anomalies)} anomalous patterns")
            
            # Build timeline structure
            timeline = await self._build_timeline_structure(
                incident_id, linked_events, anomalies
            )
            
            # Store timeline in database
            await self._store_timeline(timeline)
            
            logger.info(f"Timeline correlation completed for incident {incident_id}")
            
        except Exception as e:
            logger.error(f"Timeline correlation failed for incident {incident_id}: {e}")
            raise
    
    async def _build_timeline(self, incident_id: str):
        """Build comprehensive timeline"""
        logger.info(f"Building timeline for incident {incident_id}")
        
        try:
            # Get correlated timeline
            timeline = await self._get_stored_timeline(incident_id)
            
            if not timeline:
                logger.warning(f"No timeline found for incident {incident_id}, triggering correlation")
                await self._correlate_events(incident_id)
                timeline = await self._get_stored_timeline(incident_id)
            
            # Enrich timeline with additional context
            enriched_timeline = await self._enrich_timeline_context(timeline)
            
            # Generate visualization data
            viz_data = await self._generate_visualization_data(enriched_timeline)
            
            # Create timeline summary
            summary = await self._generate_timeline_summary(enriched_timeline)
            
            logger.info(f"Timeline building completed for incident {incident_id}")
            
            return {
                "timeline": enriched_timeline,
                "visualization": viz_data,
                "summary": summary
            }
            
        except Exception as e:
            logger.error(f"Timeline building failed for incident {incident_id}: {e}")
            raise
    
    async def _fetch_incident_events(self, incident_id: str) -> List[Dict[str, Any]]:
        """Fetch all events related to an incident from various sources"""
        events = []
        
        try:
            # Fetch from ClickHouse (high-volume logs)
            clickhouse_events = await self._fetch_from_clickhouse(incident_id)
            events.extend(clickhouse_events)
            
            # Fetch from PostgreSQL (structured events)
            postgres_events = await self._fetch_from_postgres(incident_id)
            events.extend(postgres_events)
            
            # Fetch from artifacts (parsed log events)
            artifact_events = await self._fetch_from_artifacts(incident_id)
            events.extend(artifact_events)
            
            logger.info(f"Fetched {len(events)} total events from all sources")
            return events
            
        except Exception as e:
            logger.error(f"Failed to fetch incident events: {e}")
            return []
    
    async def _fetch_from_clickhouse(self, incident_id: str) -> List[Dict[str, Any]]:
        """Fetch events from ClickHouse"""
        # TODO: Implement ClickHouse query
        # Simulate with sample data
        return [
            {
                "id": f"ch_{i}",
                "timestamp": datetime.utcnow() - timedelta(hours=i),
                "source": "siem",
                "event_type": "alert",
                "severity": "high" if i < 3 else "medium",
                "entities": [f"host_{i%3}", f"user_{i%2}"],
                "data": {"alert_id": f"ALT-{1000+i}", "rule": f"rule_{i}"}
            }
            for i in range(10)
        ]
    
    async def _fetch_from_postgres(self, incident_id: str) -> List[Dict[str, Any]]:
        """Fetch structured events from PostgreSQL"""
        # TODO: Implement PostgreSQL query
        return [
            {
                "id": f"pg_{i}",
                "timestamp": datetime.utcnow() - timedelta(minutes=i*30),
                "source": "timeline_events",
                "event_type": "user_action",
                "severity": "low",
                "entities": [f"user_{i}", f"system_{i%2}"],
                "data": {"action": f"action_{i}", "user": f"user_{i}"}
            }
            for i in range(5)
        ]
    
    async def _fetch_from_artifacts(self, incident_id: str) -> List[Dict[str, Any]]:
        """Extract events from stored artifacts"""
        # TODO: Parse artifacts and extract events
        return [
            {
                "id": f"art_{i}",
                "timestamp": datetime.utcnow() - timedelta(minutes=i*15),
                "source": "artifact_logs",
                "event_type": "system_event",
                "severity": "medium",
                "entities": [f"process_{i}", f"host_{i%2}"],
                "data": {"process": f"process_{i}", "pid": 1000+i}
            }
            for i in range(8)
        ]
    
    async def _correlate_temporal_events(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Apply temporal correlation algorithms"""
        # Sort events by timestamp
        sorted_events = sorted(events, key=lambda x: x.get('timestamp', datetime.min))
        
        # Group events within time windows
        time_window = timedelta(minutes=5)  # 5-minute correlation window
        correlated_groups = []
        current_group = []
        
        for event in sorted_events:
            if not current_group:
                current_group = [event]
            else:
                last_event_time = current_group[-1]['timestamp']
                if event['timestamp'] - last_event_time <= time_window:
                    current_group.append(event)
                else:
                    correlated_groups.append(current_group)
                    current_group = [event]
        
        if current_group:
            correlated_groups.append(current_group)
        
        # Flatten back to events with correlation metadata
        correlated_events = []
        for i, group in enumerate(correlated_groups):
            for event in group:
                event['correlation_group'] = i
                event['group_size'] = len(group)
                correlated_events.append(event)
        
        return correlated_events
    
    async def _link_entities(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Perform entity linking across events"""
        # Build entity graph
        entity_graph = {}
        
        for event in events:
            entities = event.get('entities', [])
            event_id = event['id']
            
            # Link entities that appear in the same event
            for i, entity1 in enumerate(entities):
                if entity1 not in entity_graph:
                    entity_graph[entity1] = {'events': [], 'linked_entities': set()}
                
                entity_graph[entity1]['events'].append(event_id)
                
                # Link to other entities in same event
                for entity2 in entities[i+1:]:
                    entity_graph[entity1]['linked_entities'].add(entity2)
                    
                    if entity2 not in entity_graph:
                        entity_graph[entity2] = {'events': [], 'linked_entities': set()}
                    entity_graph[entity2]['linked_entities'].add(entity1)
        
        # Add entity linking metadata to events
        for event in events:
            entities = event.get('entities', [])
            linked_entities = set()
            
            for entity in entities:
                if entity in entity_graph:
                    linked_entities.update(entity_graph[entity]['linked_entities'])
            
            event['linked_entities'] = list(linked_entities)
            event['entity_centrality'] = len(linked_entities)
        
        return events
    
    async def _detect_anomalies(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect anomalous patterns in events"""
        anomalies = []
        
        # Detect time-based anomalies
        time_anomalies = await self._detect_temporal_anomalies(events)
        anomalies.extend(time_anomalies)
        
        # Detect volume anomalies
        volume_anomalies = await self._detect_volume_anomalies(events)
        anomalies.extend(volume_anomalies)
        
        # Detect entity anomalies
        entity_anomalies = await self._detect_entity_anomalies(events)
        anomalies.extend(entity_anomalies)
        
        return anomalies
    
    async def _detect_temporal_anomalies(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect temporal anomalies (unusual timing patterns)"""
        anomalies = []
        
        # Calculate time gaps between events
        sorted_events = sorted(events, key=lambda x: x.get('timestamp', datetime.min))
        
        for i in range(1, len(sorted_events)):
            time_gap = sorted_events[i]['timestamp'] - sorted_events[i-1]['timestamp']
            
            # Flag gaps > 2 hours as potential anomalies
            if time_gap > timedelta(hours=2):
                anomalies.append({
                    "type": "temporal_gap",
                    "description": f"Unusual {time_gap.seconds//3600}h gap between events",
                    "severity": "medium",
                    "events": [sorted_events[i-1]['id'], sorted_events[i]['id']],
                    "metadata": {"gap_duration": str(time_gap)}
                })
        
        return anomalies
    
    async def _detect_volume_anomalies(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect volume anomalies (unusual event frequency)"""
        anomalies = []
        
        # Group events by hour
        hourly_counts = {}
        for event in events:
            hour = event['timestamp'].replace(minute=0, second=0, microsecond=0)
            hourly_counts[hour] = hourly_counts.get(hour, 0) + 1
        
        if not hourly_counts:
            return anomalies
        
        # Calculate average and detect spikes
        avg_count = sum(hourly_counts.values()) / len(hourly_counts)
        
        for hour, count in hourly_counts.items():
            if count > avg_count * 3:  # 3x average = anomaly
                anomalies.append({
                    "type": "volume_spike",
                    "description": f"Event volume spike: {count} events in 1 hour (avg: {avg_count:.1f})",
                    "severity": "high",
                    "timestamp": hour,
                    "metadata": {"event_count": count, "average": avg_count}
                })
        
        return anomalies
    
    async def _detect_entity_anomalies(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect entity-based anomalies"""
        anomalies = []
        
        # Count entity appearances
        entity_counts = {}
        for event in events:
            for entity in event.get('entities', []):
                entity_counts[entity] = entity_counts.get(entity, 0) + 1
        
        if not entity_counts:
            return anomalies
        
        # Detect entities with unusually high activity
        avg_count = sum(entity_counts.values()) / len(entity_counts)
        
        for entity, count in entity_counts.items():
            if count > avg_count * 5:  # 5x average = anomaly
                anomalies.append({
                    "type": "entity_hyperactivity",
                    "description": f"Entity {entity} appears in {count} events (avg: {avg_count:.1f})",
                    "severity": "medium",
                    "entity": entity,
                    "metadata": {"event_count": count, "average": avg_count}
                })
        
        return anomalies
    
    async def _build_timeline_structure(
        self, 
        incident_id: str, 
        events: List[Dict[str, Any]], 
        anomalies: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Build structured timeline from correlated events"""
        
        # Sort events chronologically
        sorted_events = sorted(events, key=lambda x: x.get('timestamp', datetime.min))
        
        # Group events into phases
        phases = await self._identify_incident_phases(sorted_events)
        
        # Create timeline structure
        timeline = {
            "incident_id": incident_id,
            "created_at": datetime.utcnow().isoformat(),
            "total_events": len(sorted_events),
            "phases": phases,
            "anomalies": anomalies,
            "events": sorted_events,
            "metadata": {
                "correlation_algorithm": "temporal_clustering",
                "entity_linking": "graph_based",
                "anomaly_detection": "statistical_outliers"
            }
        }
        
        return timeline
    
    async def _identify_incident_phases(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify distinct phases of the incident"""
        phases = []
        
        if not events:
            return phases
        
        # Simple phase detection based on event density and severity
        current_phase = {
            "name": "initial_detection",
            "start_time": events[0]['timestamp'].isoformat(),
            "events": [],
            "severity": "low"
        }
        
        for event in events:
            # Simple heuristic: new phase if gap > 1 hour or severity spike
            if (len(current_phase['events']) > 0):
                last_event_time = datetime.fromisoformat(current_phase['events'][-1]['timestamp'].isoformat())
                time_gap = event['timestamp'] - last_event_time
                
                if time_gap.seconds > 3600:  # 1 hour gap
                    current_phase['end_time'] = current_phase['events'][-1]['timestamp'].isoformat()
                    phases.append(current_phase)
                    
                    current_phase = {
                        "name": f"phase_{len(phases) + 1}",
                        "start_time": event['timestamp'].isoformat(),
                        "events": [],
                        "severity": "low"
                    }
            
            current_phase['events'].append(event)
            
            # Update phase severity
            if event.get('severity') == 'critical':
                current_phase['severity'] = 'critical'
            elif event.get('severity') == 'high' and current_phase['severity'] != 'critical':
                current_phase['severity'] = 'high'
        
        # Close final phase
        if current_phase['events']:
            current_phase['end_time'] = current_phase['events'][-1]['timestamp'].isoformat()
            phases.append(current_phase)
        
        return phases
    
    async def _store_timeline(self, timeline: Dict[str, Any]) -> None:
        """Store timeline in database"""
        # TODO: Store in PostgreSQL timeline table
        logger.info(f"Storing timeline for incident {timeline['incident_id']}")
    
    async def _get_stored_timeline(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve stored timeline from database"""
        # TODO: Query PostgreSQL for timeline
        return None
    
    async def _enrich_timeline_context(self, timeline: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich timeline with additional context and annotations"""
        # Add threat intelligence context
        # Add user behavior context
        # Add system baseline context
        return timeline
    
    async def _generate_visualization_data(self, timeline: Dict[str, Any]) -> Dict[str, Any]:
        """Generate data for timeline visualization"""
        return {
            "timeline_data": {
                "events": timeline.get('events', []),
                "phases": timeline.get('phases', []),
                "anomalies": timeline.get('anomalies', [])
            },
            "chart_config": {
                "type": "timeline",
                "time_range": {
                    "start": timeline['events'][0]['timestamp'].isoformat() if timeline.get('events') else None,
                    "end": timeline['events'][-1]['timestamp'].isoformat() if timeline.get('events') else None
                },
                "zoom_levels": ["1h", "6h", "1d", "1w"]
            }
        }
    
    async def _generate_timeline_summary(self, timeline: Dict[str, Any]) -> Dict[str, Any]:
        """Generate executive summary of timeline"""
        events = timeline.get('events', [])
        phases = timeline.get('phases', [])
        anomalies = timeline.get('anomalies', [])
        
        return {
            "total_events": len(events),
            "total_phases": len(phases),
            "anomalies_detected": len(anomalies),
            "duration": self._calculate_incident_duration(events),
            "severity_distribution": self._calculate_severity_distribution(events),
            "key_findings": self._extract_key_findings(events, anomalies)
        }
    
    def _calculate_incident_duration(self, events: List[Dict[str, Any]]) -> str:
        """Calculate total incident duration"""
        if len(events) < 2:
            return "0 minutes"
        
        start = min(event['timestamp'] for event in events)
        end = max(event['timestamp'] for event in events)
        duration = end - start
        
        hours = duration.seconds // 3600
        minutes = (duration.seconds % 3600) // 60
        
        return f"{hours}h {minutes}m"
    
    def _calculate_severity_distribution(self, events: List[Dict[str, Any]]) -> Dict[str, int]:
        """Calculate distribution of event severities"""
        distribution = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        
        for event in events:
            severity = event.get('severity', 'low')
            if severity in distribution:
                distribution[severity] += 1
        
        return distribution
    
    def _extract_key_findings(self, events: List[Dict[str, Any]], anomalies: List[Dict[str, Any]]) -> List[str]:
        """Extract key findings from timeline analysis"""
        findings = []
        
        # High severity events
        high_severity_count = sum(1 for e in events if e.get('severity') in ['high', 'critical'])
        if high_severity_count > 0:
            findings.append(f"Detected {high_severity_count} high/critical severity events")
        
        # Anomalies
        if anomalies:
            findings.append(f"Identified {len(anomalies)} anomalous patterns requiring investigation")
        
        # Event clustering
        if len(events) > 10:
            findings.append("High event volume suggests coordinated attack or system compromise")
        
        return findings
