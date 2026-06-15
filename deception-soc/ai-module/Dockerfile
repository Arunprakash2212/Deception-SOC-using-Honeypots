FROM python:3.11-slim

LABEL maintainer="deception-soc"
LABEL component="ai-module"

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/

# Create models directory
RUN mkdir -p /app/models

EXPOSE 8500

ENV MODEL_DIR=/app/models

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8500/api/v1/ai/health')" || exit 1

CMD ["python", "-m", "uvicorn", "app.api:app", "--host", "0.0.0.0", "--port", "8500"]
