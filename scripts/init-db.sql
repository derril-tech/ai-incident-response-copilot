-- Enable pgvector extension
CREATE EXTENSION IF NOT EXISTS vector;

-- Create database for incident response
-- (Database is already created via POSTGRES_DB env var)

-- Create additional schemas if needed
CREATE SCHEMA IF NOT EXISTS audit;
CREATE SCHEMA IF NOT EXISTS analytics;

-- Grant permissions
GRANT ALL PRIVILEGES ON DATABASE incident_response TO postgres;
GRANT ALL PRIVILEGES ON SCHEMA public TO postgres;
GRANT ALL PRIVILEGES ON SCHEMA audit TO postgres;
GRANT ALL PRIVILEGES ON SCHEMA analytics TO postgres;
