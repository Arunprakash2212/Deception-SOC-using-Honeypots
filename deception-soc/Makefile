.PHONY: build up down logs test status clean build-honeypots help

# Default target
help:
	@echo "=============================================="
	@echo "  Deception-SOC Makefile Commands"
	@echo "=============================================="
	@echo "  make build           Build all Docker images"
	@echo "  make build-honeypots Build honeypot images only"
	@echo "  make up              Start all services"
	@echo "  make down            Stop all services"
	@echo "  make logs            Follow all service logs"
	@echo "  make test            Run attack simulation"
	@echo "  make status          Check service health"
	@echo "  make clean           Stop services and clean up"
	@echo "  make unit-tests      Run unit tests"
	@echo "=============================================="

# Build honeypot images separately (needed for dynamic deployment)
build-honeypots:
	@echo "[*] Building honeypot images..."
	docker build -t deception-soc/ssh-honeypot:latest ./honeypots/ssh-honeypot/
	docker build -t deception-soc/http-honeypot:latest ./honeypots/http-honeypot/
	docker build -t deception-soc/ftp-honeypot:latest ./honeypots/ftp-honeypot/
	@echo "[✓] Honeypot images built successfully"

# Build everything
build: build-honeypots
	@echo "[*] Building all services..."
	docker-compose build
	@echo "[✓] All images built successfully"

# Start all services
up:
	@echo "[*] Starting Deception-SOC..."
	docker-compose up -d
	@echo ""
	@echo "[✓] Services starting. Check status with: make status"
	@echo "    Dashboard: http://localhost:3000"
	@echo "    Kibana:    http://localhost:5601"

# Stop all services
down:
	@echo "[*] Stopping Deception-SOC..."
	docker-compose down
	@echo "[✓] All services stopped"

# Follow logs
logs:
	docker-compose logs -f

# Run attack simulation
test:
	@echo "[*] Running attack simulation..."
	python tests/simulate_attacker.py localhost

# Check service health
status:
	@echo "[*] Checking service health..."
	@echo ""
	@echo "--- Orchestrator ---"
	@curl -s http://localhost:8000/api/v1/health 2>/dev/null | python -m json.tool 2>/dev/null || echo "  ✗ Not reachable"
	@echo ""
	@echo "--- Logger ---"
	@curl -s http://localhost:9000/api/v1/stats 2>/dev/null | python -m json.tool 2>/dev/null || echo "  ✗ Not reachable"
	@echo ""
	@echo "--- AI Module ---"
	@curl -s http://localhost:8500/api/v1/ai/status 2>/dev/null | python -m json.tool 2>/dev/null || echo "  ✗ Not reachable"
	@echo ""
	@echo "--- Elasticsearch ---"
	@curl -s http://localhost:9200/_cluster/health 2>/dev/null | python -m json.tool 2>/dev/null || echo "  ✗ Not reachable"

# Run unit tests
unit-tests:
	@echo "[*] Running unit tests..."
	python -m pytest tests/ -v --tb=short 2>/dev/null || python -m unittest discover -s tests -v

# Full cleanup
clean:
	@echo "[*] Full cleanup..."
	docker-compose down -v
	docker system prune -f --filter "label=deception-soc"
	@echo "[✓] Cleanup complete"
