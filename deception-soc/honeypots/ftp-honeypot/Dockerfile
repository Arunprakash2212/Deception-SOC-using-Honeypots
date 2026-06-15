FROM python:3.11-slim

LABEL maintainer="deception-soc"
LABEL component="ftp-honeypot"

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY fake_ftp.py .

EXPOSE 21
EXPOSE 60000-60100

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import socket; s=socket.socket(); s.connect(('localhost',21)); s.close()" || exit 1

CMD ["python", "-u", "fake_ftp.py"]
