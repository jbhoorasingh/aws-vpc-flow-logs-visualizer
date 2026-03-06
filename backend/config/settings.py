from pathlib import Path
from urllib.parse import parse_qsl, unquote, urlparse
import os

from django.core.exceptions import ImproperlyConfigured

BASE_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIST_DIR = BASE_DIR / "frontend_dist"
FRONTEND_ASSETS_DIR = FRONTEND_DIST_DIR / "assets"

SECRET_KEY = os.getenv("DJANGO_SECRET_KEY", "dev-only-secret-key")
DEBUG = os.getenv("DJANGO_DEBUG", "false").lower() == "true"
ALLOWED_HOSTS = [host for host in os.getenv("DJANGO_ALLOWED_HOSTS", "*").split(",") if host]

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "corsheaders",
    "rest_framework",
    "flows",
]

MIDDLEWARE = [
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates", FRONTEND_DIST_DIR],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"
ASGI_APPLICATION = "config.asgi.application"


def _database_config():
    database_url = (
        os.getenv("DJANGO_DATABASE_URL")
        or os.getenv("DATABASE_URL")
        or os.getenv("POSTGRESQL_URL")
    )
    if not database_url:
        return {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": BASE_DIR / "db.sqlite3",
        }

    parsed = urlparse(database_url)
    scheme = (parsed.scheme or "").lower()

    if scheme in {"postgres", "postgresql", "pgsql"}:
        database_name = unquote((parsed.path or "").lstrip("/"))
        if not database_name:
            raise ImproperlyConfigured(
                "PostgreSQL URL is missing database name. "
                "Expected format: postgresql://user:password@host:5432/dbname"
            )

        config = {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": database_name,
            "USER": unquote(parsed.username or ""),
            "PASSWORD": unquote(parsed.password or ""),
            "HOST": parsed.hostname or "",
            "PORT": str(parsed.port or ""),
        }
        query_options = {
            key: value
            for key, value in parse_qsl(parsed.query, keep_blank_values=True)
            if key
        }
        if query_options:
            config["OPTIONS"] = query_options

        return config

    if scheme == "sqlite":
        if database_url.endswith(":memory:"):
            database_name = ":memory:"
        else:
            database_name = unquote(parsed.path or "")
            if parsed.netloc:
                database_name = f"/{parsed.netloc}{database_name}"
            if not database_name:
                raise ImproperlyConfigured(
                    "SQLite URL is missing database path. "
                    "Expected format: sqlite:////absolute/path/to/db.sqlite3"
                )

        return {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": database_name,
        }

    raise ImproperlyConfigured(
        "Unsupported database URL scheme "
        f"'{parsed.scheme}'. Supported: postgres/postgresql or sqlite."
    )


DATABASES = {
    "default": _database_config()
}

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

DATA_UPLOAD_MAX_NUMBER_FILES = int(os.getenv("DATA_UPLOAD_MAX_NUMBER_FILES", "10000"))
DATA_UPLOAD_MAX_MEMORY_SIZE = int(os.getenv("DATA_UPLOAD_MAX_MEMORY_SIZE", str(500 * 1024 * 1024)))

CORS_ALLOW_ALL_ORIGINS = os.getenv("CORS_ALLOW_ALL_ORIGINS", "true").lower() == "true"

REST_FRAMEWORK = {
    "DEFAULT_PAGINATION_CLASS": "flows.pagination.StandardResultsSetPagination",
    "PAGE_SIZE": 100,
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "flows.auth.EnvAccountAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": [
        "flows.auth.EnvAccountPermission",
    ],
    "DEFAULT_SCHEMA_CLASS": "rest_framework.schemas.openapi.AutoSchema",
}
