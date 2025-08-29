import asyncio
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
import structlog
from src.api.routes import router
from src.core.config import settings
from src.core.database import init_db
from src.core.messaging import init_nats
from src.workers.collector import CollectorWorker
from src.workers.timeline import TimelineWorker
from src.workers.forensic import ForensicWorker
from src.workers.report import ReportWorker
from src.workers.export import ExportWorker

# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer()
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger()

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    logger.info("Starting AI Incident Response Orchestrator")
    
    # Initialize database
    await init_db()
    
    # Initialize NATS connection
    await init_nats()
    
    # Start workers
    workers = [
        CollectorWorker(),
        TimelineWorker(),
        ForensicWorker(),
        ReportWorker(),
        ExportWorker(),
    ]
    
    tasks = []
    for worker in workers:
        task = asyncio.create_task(worker.start())
        tasks.append(task)
        logger.info(f"Started {worker.__class__.__name__}")
    
    yield
    
    # Cleanup
    logger.info("Shutting down orchestrator")
    for task in tasks:
        task.cancel()
    
    await asyncio.gather(*tasks, return_exceptions=True)

app = FastAPI(
    title="AI Incident Response Orchestrator",
    description="CrewAI-powered orchestration for incident response automation",
    version="1.0.0",
    lifespan=lifespan,
)

# Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(GZipMiddleware, minimum_size=1000)

# Routes
app.include_router(router, prefix="/api/v1")

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "orchestrator",
        "version": "1.0.0"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.DEBUG,
        log_level="info"
    )
