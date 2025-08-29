from typing import Dict, Any, List, Optional
import structlog
from datetime import datetime, timedelta
import json
from .base import BaseWorker
from ..services.timeline_correlator import TimelineCorrelator
from ..services.entity_linker import EntityLinker
from ..services.anomaly_detector import AnomalyDetector

logger = structlog.get_logger()

class TimelineWorker(BaseWorker):
    """Worker for timeline correlation and analysis"""
    
    def __init__(self):
        super().__init__("timeline", ["timeline.build", "timeline.correlate"])
        self.correlator = TimelineCorrelator()
        self.entity_linker = EntityLinker()
        self.anomaly_detector = AnomalyDetector()
    
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
            correlated_events = await self.correlator.correlate_temporal_events(events)
            logger.info(f"Correlated into {len(correlated_events)} event clusters")
            
            # Perform entity linking
            linked_events = await self.entity_linker.link_entities(correlated_events)
            logger.info(f"Linked entities across {len(linked_events)} events")
            
            # Detect anomalies
            anomalies = await self.anomaly_detector.detect_anomalies(linked_events)
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
    
    async def _simulate_correlation(self, incident_id: str):
        """Simulate event correlation for demo purposes"""
        import asyncio
        
        events = [
            {"timestamp": "2023-12-01T10:00:00Z", "type": "alert", "severity": "high"},
            {"timestamp": "2023-12-01T10:05:00Z", "type": "log_entry", "severity": "medium"},
            {"timestamp": "2023-12-01T10:10:00Z", "type": "user_action", "severity": "low"},
        ]
        
        for event in events:
            logger.info(f"Correlating event: {event['type']}")
            await asyncio.sleep(0.5)
            
        logger.info(f"Timeline correlation completed for incident {incident_id}")
