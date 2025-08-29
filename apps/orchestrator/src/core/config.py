from pydantic_settings import BaseSettings
from typing import List

class Settings(BaseSettings):
    # Application
    DEBUG: bool = False
    ALLOWED_ORIGINS: List[str] = ["http://localhost:3000", "http://localhost:3001"]
    
    # Database
    DATABASE_URL: str = "postgresql+asyncpg://postgres:password@localhost:5432/incident_response"
    CLICKHOUSE_URL: str = "http://localhost:8123"
    
    # Redis
    REDIS_URL: str = "redis://localhost:6379"
    
    # NATS
    NATS_URL: str = "nats://localhost:4222"
    
    # S3/MinIO
    S3_ENDPOINT: str = "http://localhost:9000"
    S3_ACCESS_KEY: str = "minioadmin"
    S3_SECRET_KEY: str = "minioadmin123"
    S3_BUCKET: str = "incident-artifacts"
    
    # AI/LLM
    OPENAI_API_KEY: str = ""
    ANTHROPIC_API_KEY: str = ""
    
    # Security
    SECRET_KEY: str = "your-secret-key-change-in-production"
    
    # External APIs
    JIRA_URL: str = ""
    JIRA_USERNAME: str = ""
    JIRA_API_TOKEN: str = ""
    
    SERVICENOW_URL: str = ""
    SERVICENOW_USERNAME: str = ""
    SERVICENOW_PASSWORD: str = ""
    
    class Config:
        env_file = ".env"

settings = Settings()
