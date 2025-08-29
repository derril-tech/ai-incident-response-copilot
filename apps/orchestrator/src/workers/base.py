import asyncio
import json
from abc import ABC, abstractmethod
from typing import Dict, Any
import structlog
from ..core.messaging import get_nats

logger = structlog.get_logger()

class BaseWorker(ABC):
    """Base class for all workers"""
    
    def __init__(self, name: str, subjects: list):
        self.name = name
        self.subjects = subjects
        self.running = False
        
    async def start(self):
        """Start the worker"""
        self.running = True
        logger.info(f"Starting {self.name} worker")
        
        nats_conn = await get_nats()
        
        # Subscribe to subjects
        for subject in self.subjects:
            await nats_conn.subscribe(subject, self._handle_message)
            logger.info(f"{self.name} subscribed to {subject}")
        
        # Keep worker running
        while self.running:
            await asyncio.sleep(1)
    
    async def stop(self):
        """Stop the worker"""
        self.running = False
        logger.info(f"Stopping {self.name} worker")
    
    async def _handle_message(self, msg):
        """Handle incoming NATS message"""
        try:
            data = json.loads(msg.data.decode())
            logger.info(f"{self.name} received message", subject=msg.subject, data=data)
            
            await self.process_message(msg.subject, data)
            await msg.ack()
            
        except Exception as e:
            logger.error(f"Error processing message in {self.name}", error=str(e))
            await msg.nak()
    
    @abstractmethod
    async def process_message(self, subject: str, data: Dict[str, Any]):
        """Process the message - to be implemented by subclasses"""
        pass
