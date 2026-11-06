# Production-grade Dockerfile for VulnTracker FastAPI service
# Minimal, pinned base image
FROM python:3.11.8-slim-bookworm

# Prevent Python from writing .pyc files and enable unbuffered logging
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PORT=8000

# Set working directory
WORKDIR /app

# Create non-privileged user and group
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -s /sbin/nologin -d /app appuser

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY app/ /app/

# Set ownership to non-root user
RUN chown -R appuser:appgroup /app

# Switch to non-root user
USER 10001:10001

# Expose service port
EXPOSE 8000

# Container healthcheck using standard library urllib (no curl required)
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request, sys; sys.exit(0 if urllib.request.urlopen('http://localhost:8000/health').getcode() == 200 else 1)"

# Start uvicorn server from /app where modules can resolve bare imports
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]

