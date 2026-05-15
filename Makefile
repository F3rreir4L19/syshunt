.PHONY: up up-local up-all down migrate test worker dashboard lint format seed

# ─── Infraestrutura ─────────────────────────────────────────

# Start database and Redis only (notebook / local dev — no worker or dashboard container)
up:
	docker-compose up -d db redis

# Start all services with local port bindings (development only — NOT for VPS)
up-local:
	docker-compose -f docker-compose.yml -f docker-compose.local.yml up -d

# Start all services without exposing internal ports (VPS / production)
up-all:
	docker-compose up -d

logs:
	docker-compose logs -f worker dashboard

# ─── Banco de Dados ──────────────────────────────────────────
migrate:
	alembic upgrade head

migrate-new:
	alembic revision --autogenerate -m "$(MSG)"

migrate-down:
	alembic downgrade -1

seed:
	python -m core.db.seed

# ─── Desenvolvimento ─────────────────────────────────────────
worker:
	celery -A core.pipeline.tasks worker --loglevel=info --concurrency=4

beat:
	celery -A core.pipeline.tasks beat --loglevel=info

flower:
	celery -A core.pipeline.tasks flower --port=5555

dashboard:
	streamlit run dashboard/app.py --server.port=8501

# ─── Qualidade ───────────────────────────────────────────────
test:
	pytest tests/ -v --tb=short

test-cov:
	pytest tests/ --cov=core --cov=tools --cov-report=term-missing

lint:
	ruff check core/ tools/ dashboard/

format:
	black core/ tools/ dashboard/
	ruff check --fix core/ tools/ dashboard/

# ─── Docker Build ────────────────────────────────────────────
build:
	docker-compose build

rebuild:
	docker-compose build --no-cache
