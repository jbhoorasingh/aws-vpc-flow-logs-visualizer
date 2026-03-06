FROM node:20-alpine AS frontend-builder

WORKDIR /app/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci

COPY frontend/ ./
ARG VITE_API_BASE_URL=/api
ENV VITE_API_BASE_URL=${VITE_API_BASE_URL}
RUN npm run build


FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DJANGO_DEBUG=false \
    DJANGO_ALLOWED_HOSTS=* \
    CORS_ALLOW_ALL_ORIGINS=true

WORKDIR /app

RUN pip install --no-cache-dir \
    "django>=5.1,<6.0" \
    "djangorestframework>=3.16,<4.0" \
    "django-cors-headers>=4.6,<5.0" \
    "psycopg[binary]>=3.2,<4.0" \
    "gunicorn>=22,<24"

COPY backend/ /app/backend/
COPY --from=frontend-builder /app/frontend/dist/ /app/backend/frontend_dist/

WORKDIR /app/backend
EXPOSE 8000

CMD ["sh", "-c", "python manage.py migrate && gunicorn config.wsgi:application --bind 0.0.0.0:8000 --workers 3 --timeout 600"]
