# Stage 1: Build Frontend
FROM node:20-alpine AS frontend-builder
WORKDIR /build/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# Stage 2: Runtime Container
FROM python:3.12-slim AS runner

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive

# Install system utilities needed for discovery & networking
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Create unprivileged user
RUN groupadd -g 10001 pretweb && \
    useradd -u 10001 -g pretweb -m -s /bin/bash pretweb

# Copy backend requirements and install
COPY backend/requirements.txt ./backend/requirements.txt
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r ./backend/requirements.txt

# Copy vendored PRET source
COPY pret/ ./pret/

# Copy backend code
COPY backend/ ./backend/

# Copy built frontend assets from stage 1
COPY --from=frontend-builder /build/backend/app/static/ ./backend/app/static/

# Set up data directories and permissions
RUN mkdir -p /app/backend/data/jobs && \
    chown -R pretweb:pretweb /app

USER pretweb

EXPOSE 8443

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://0.0.0.0:8443/healthz || exit 1

WORKDIR /app/backend
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8443"]
