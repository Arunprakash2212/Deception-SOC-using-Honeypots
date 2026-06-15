FROM python:3.11-slim

LABEL maintainer="deception-soc"
LABEL component="detection-engine"

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

# Create log directory
RUN mkdir -p /var/log/suricata

# Copy requirements and install Python dependencies
COPY log-watcher/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY log-watcher/watcher.py .

# Health check
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import os; assert os.path.exists('/var/log/suricata/eve.json')" || exit 1

CMD ["python", "-u", "watcher.py"]
