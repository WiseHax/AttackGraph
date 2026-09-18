FROM python:3.12-slim

# J-19: Create unprivileged user and group
RUN groupadd -r attackgraph && useradd -r -g attackgraph attackgraph

WORKDIR /app

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libpq-dev && \
    rm -rf /var/lib/apt/lists/*

# Dependency workflow: Install strictly from lockfile with hashes
COPY requirements.lock .
RUN pip install --no-cache-dir --require-hashes -r requirements.lock

COPY . .

# Generate engine metadata as ROOT
ARG APP_GIT_COMMIT
ARG APP_GIT_DIRTY
ENV APP_GIT_COMMIT=${APP_GIT_COMMIT}
ENV APP_GIT_DIRTY=${APP_GIT_DIRTY}
RUN python scripts/generate_metadata.py

# J-19: Lock down metadata file
RUN chown root:root engine_metadata.json && \
    chmod 0444 engine_metadata.json

# J-19: Switch to unprivileged user
USER attackgraph

CMD ["sh", "-c", "alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port 8000"]
