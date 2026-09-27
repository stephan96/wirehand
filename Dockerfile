FROM python:3.12-slim

# Match the host user that owns the bind-mounted config (default uid/gid 1000).
# Build with:  docker compose build --build-arg APP_UID=$(id -u) --build-arg APP_GID=$(id -g)
ARG APP_UID=1000
ARG APP_GID=1000
RUN groupadd --gid ${APP_GID} appuser 2>/dev/null || true \
 && useradd --create-home --uid ${APP_UID} --gid ${APP_GID} appuser \
 && apt-get update && apt-get install -y --no-install-recommends openssh-client curl \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --chown=appuser:appuser requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# COPY --chown: otherwise host file modes (e.g. 600) carry over -> PermissionError as non-root
COPY --chown=appuser:appuser app ./app

RUN mkdir -p /app/data /app/config && chown -R appuser:appuser /app
USER appuser
EXPOSE 8110
HEALTHCHECK --interval=15s --timeout=5s --retries=5 CMD curl -sf http://localhost:8110/health || exit 1
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8110", "--workers", "1"]
