FROM python:3.11-slim

LABEL maintainer="deception-soc"
LABEL component="logger"

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/

EXPOSE 9000

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:9000/api/v1/health')" || exit 1

CMD ["python", "-m", "uvicorn", "app.session_logger:app", "--host", "0.0.0.0", "--port", "9000"]
