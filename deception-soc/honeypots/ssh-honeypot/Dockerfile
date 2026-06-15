FROM python:3.11-slim

LABEL maintainer="deception-soc"
LABEL component="ssh-honeypot"

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-client \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Generate SSH host key at build time using ssh-keygen
RUN ssh-keygen -t rsa -b 2048 -f /app/ssh_host_key -N "" -q

COPY fake_ssh.py .

EXPOSE 22

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import socket; s=socket.socket(); s.connect(('localhost',22)); s.close()" || exit 1

CMD ["python", "-u", "fake_ssh.py"]
