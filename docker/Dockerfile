FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    DJANGO_SETTINGS_MODULE=core.settings.prod \
    PATH="/root/.local/bin:$PATH"

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      gettext \
      libpq5 \
      curl \
    && rm -rf /var/lib/apt/lists/*

# Install uv (modern Python package manager)
RUN pip install --no-cache-dir uv==0.5.30

WORKDIR /app

# Install dependencies (cache layer)
COPY app/pyproject.toml ./
RUN uv pip install --system -r pyproject.toml

# Copy application code
COPY app/ .

# Build assets (each step separate to surface errors)
RUN python manage.py tailwind build
RUN python manage.py collectstatic --noinput
RUN python manage.py compilemessages --ignore=.venv 2>/dev/null || true

COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

RUN mkdir -p /app/data /app/media

EXPOSE 8000

ENTRYPOINT ["/entrypoint.sh"]
CMD ["gunicorn", "core.wsgi:application", \
     "--bind", "0.0.0.0:8000", \
     "--workers", "2", \
     "--threads", "2", \
     "--worker-class", "gthread", \
     "--max-requests", "1000", \
     "--max-requests-jitter", "50", \
     "--access-logfile", "-", \
     "--error-logfile", "-"]
