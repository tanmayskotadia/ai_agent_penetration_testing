FROM node:24-alpine@sha256:8a32c8cf649a49915a66e81e7a609223c708d0adabf288ee3f4077d765542f85 AS frontend-build
WORKDIR /frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim-bookworm@sha256:e697c81897302a4c4333bade000d98038fbb21eb064f8ee1fd42d02ebcd9d337
ENV PYTHONUNBUFFERED=1 UV_PYTHON_DOWNLOADS=never UV_CACHE_DIR=/tmp/uv-cache UV_LINK_MODE=copy
RUN pip install --no-cache-dir uv==0.12.13 && useradd --create-home --uid 10001 app
WORKDIR /app
COPY --chown=10001:10001 pyproject.toml uv.lock README.md alembic.ini ./
COPY --chown=10001:10001 backend/ backend/
COPY --chown=10001:10001 workers/ workers/
COPY --chown=10001:10001 reports/ reports/
COPY --chown=10001:10001 migrations/ migrations/
COPY --from=frontend-build --chown=10001:10001 /frontend/dist/ frontend/dist/
RUN chown 10001:10001 /app
USER 10001
RUN uv sync --frozen --no-dev
EXPOSE 8000
CMD ["uv", "run", "--no-sync", "uvicorn", "aegistrace.api:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
