FROM python:3.11-slim

LABEL maintainer="deception-soc"
LABEL component="http-honeypot"

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY fake_webapp.py .
COPY templates/ ./templates/

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:80/health')" || exit 1

CMD ["python", "-u", "fake_webapp.py"]
