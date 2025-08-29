FROM python:3.11-slim AS builder

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Production stage
FROM python:3.11-slim AS production

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN adduser --disabled-password --gecos '' --uid 1001 appuser

# Copy Python packages from builder
COPY --from=builder /root/.local /home/appuser/.local

# Copy application code
COPY --chown=appuser:appuser . .

# Make sure scripts are executable
RUN chmod +x /home/appuser/.local/bin/*

USER appuser

# Add local bin to PATH
ENV PATH=/home/appuser/.local/bin:$PATH

EXPOSE 8000

CMD ["python", "main.py"]
