import nats
from nats.js import JetStreamContext
from .config import settings
import structlog

logger = structlog.get_logger()

class NATSConnection:
    def __init__(self):
        self.nc = None
        self.js = None
    
    async def connect(self):
        """Connect to NATS server"""
        try:
            self.nc = await nats.connect(settings.NATS_URL)
            self.js = self.nc.jetstream()
            
            # Create streams for incident processing
            await self._create_streams()
            
            logger.info("Connected to NATS server")
        except Exception as e:
            logger.error(f"Failed to connect to NATS: {e}")
            raise
    
    async def _create_streams(self):
        """Create JetStream streams for incident processing"""
        streams = [
            {
                "name": "INCIDENTS",
                "subjects": ["incident.*"],
                "retention": "workqueue",
            },
            {
                "name": "ARTIFACTS", 
                "subjects": ["artifact.*"],
                "retention": "workqueue",
            },
            {
                "name": "TIMELINES",
                "subjects": ["timeline.*"], 
                "retention": "workqueue",
            },
            {
                "name": "REPORTS",
                "subjects": ["report.*"],
                "retention": "workqueue",
            }
        ]
        
        for stream_config in streams:
            try:
                await self.js.add_stream(**stream_config)
                logger.info(f"Created stream: {stream_config['name']}")
            except Exception as e:
                if "already exists" not in str(e):
                    logger.error(f"Failed to create stream {stream_config['name']}: {e}")
    
    async def publish(self, subject: str, data: bytes):
        """Publish message to NATS"""
        if self.js:
            await self.js.publish(subject, data)
    
    async def subscribe(self, subject: str, callback):
        """Subscribe to NATS subject"""
        if self.nc:
            await self.nc.subscribe(subject, cb=callback)
    
    async def close(self):
        """Close NATS connection"""
        if self.nc:
            await self.nc.close()

# Global NATS connection
nats_conn = NATSConnection()

async def init_nats():
    """Initialize NATS connection"""
    await nats_conn.connect()

async def get_nats():
    """Get NATS connection"""
    return nats_conn
