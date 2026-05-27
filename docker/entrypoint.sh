#!/bin/sh
set -e

if [ "${SKIP_MIGRATIONS:-0}" = "1" ]; then
    echo "SKIP_MIGRATIONS=1 → migrations skipped (staging mode, run them from prod)."
else
    echo "Running migrations..."
    python manage.py migrate --noinput
fi

echo "Collecting static files..."
python manage.py collectstatic --noinput

echo "Compiling translations..."
python manage.py compilemessages --ignore=.venv 2>/dev/null || true

exec "$@"
