import os
from pathlib import Path
import environ
import sys  
import logging



# Initialize environment variables
env = environ.Env()
environ.Env.read_env(os.path.join(Path(__file__).resolve().parent.parent, '.env'))

# Set up logging for debugging environment variables
logger = logging.getLogger(__name__)

# Paths
BASE_DIR = Path(__file__).resolve().parent.parent

# Security
SECRET_KEY = env('DJANGO_SECRET_KEY', default='change-me-in-production')
DEBUG = env.bool('DJANGO_DEBUG', default=False)
ALLOWED_HOSTS = env('DJANGO_ALLOWED_HOSTS', default='localhost,127.0.0.1').split(',')
CORS_ALLOWED_ORIGINS = env('CORS_ALLOWED_ORIGINS', default='http://localhost:3000').split(',')
CSRF_TRUSTED_ORIGINS = env('CSRF_TRUSTED_ORIGINS', default='http://localhost:3000').split(',')

# Optional: expose referral client URLs to settings
# Default to local/test hosts if not provided in .env
REFERRAL_CLIENT_URLS = env(
    'REFERRAL_CLIENT_URLS',
    default='https://client.localhost/register,https://client.vtifx/register,https://admin.localhost/register,https://admin.vtifx/register',
).split(',')

# URL handling
APPEND_SLASH = True  # Ensure Django handles trailing slashes correctly

# Applications
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'channels',  # Add Channels for WebSocket support
    'corsheaders',
    'rest_framework',
    'rest_framework_simplejwt',
    'rest_framework_simplejwt.token_blacklist',
    'django_hosts',
    'django_extensions',
    'django_celery_beat',  # Add for scheduled tasks
    'brokerBackend.apps.BrokerBackendConfig',  # Add broker backend app config
    'adminPanel',
    'adminPanel.mt5',  # Add the MT5 app
    'clientPanel',
]

# Middleware
MIDDLEWARE = [
    # CRITICAL SECURITY: Block source code and sensitive files FIRST
    'brokerBackend.source_code_protection.SourceCodeProtectionMiddleware',
    'brokerBackend.middleware.GlobalSecurityHeadersMiddleware',
    'django_hosts.middleware.HostsRequestMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'brokerBackend.middleware.NoCacheMiddleware',  # Add no-cache middleware for development
    'brokerBackend.api_middleware.APIJSONResponseMiddleware',  # Ensure API endpoints return JSON
    'django.middleware.security.SecurityMiddleware',
    'brokerBackend.middleware.SecurityHeadersMiddleware',
    'brokerBackend.middleware.StaticFilesSecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    # 'brokerBackend.middleware.SubdomainMiddleware',  # Corrected path
    'brokerBackend.middleware.ClientCSRFExemptMiddleware',  # Add CSRF exemption BEFORE CSRF middleware
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'brokerBackend.middleware.WebhookProtectionMiddleware',
    # 'clientPanel.middleware.ClientAuthGuardMiddleware',  # Client panel authentication guard
    'brokerBackend.middleware.EarlyAPIAuthMiddleware',
    'brokerBackend.middleware.AdminHostRestrictMiddleware',
    'brokerBackend.middleware.AdminAPIEnforceMiddleware',
    'brokerBackend.middleware.AdminAuthenticationMiddleware',  # Corrected path
    'django.contrib.messages.middleware.MessageMiddleware',
    'brokerBackend.middleware.RequestAbuseLoggingMiddleware',
    'brokerBackend.request_logger.RequestLoggingMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'adminPanel.middleware.IPAddressMiddleware',
    'adminPanel.middleware.activity_logging.ActivityLoggingMiddleware',
    'adminPanel.role_middleware.RoleBasedAccessMiddleware',
    'django_hosts.middleware.HostsResponseMiddleware',
]


# URLs and WSGI/ASGI
ROOT_URLCONF = 'brokerBackend.urls'
WSGI_APPLICATION = 'brokerBackend.wsgi.application'
ASGI_APPLICATION = 'brokerBackend.asgi.application'

# Templates
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [
            os.path.join(BASE_DIR, 'templates'),  # Root templates directory for error pages
            os.path.join(BASE_DIR, 'clientPanel', 'templates'),
        ],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]
USE_X_FORWARDED_HOST = True

# Database
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': env('DB_NAME', default='default_db_name'),
        'USER': env('DB_USER', default='default_user'),
        'PASSWORD': env('DB_PASSWORD', default='default_password'),
        'HOST': env('DB_HOST', default='localhost'),
        # Default Postgres port is 5432; override with DB_PORT env if different
        'PORT': env('DB_PORT', default='5432'),
        # Keep connections open briefly to enable reuse (seconds)
        'CONN_MAX_AGE': env.int('DB_CONN_MAX_AGE', default=60),
        # Use atomic requests to ensure connections are returned at request end
        'ATOMIC_REQUESTS': True,
    }
}

# Password Validation
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

# Internationalization
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

# Static Files Configuration
STATIC_URL = '/static/'
STATICFILES_DIRS = [
    os.path.join(BASE_DIR, 'static'),
]
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')

# Allow WhiteNoise to use staticfiles finders so `runserver` can serve files
# placed in `STATICFILES_DIRS` without needing `collectstatic` during local testing.
WHITENOISE_USE_FINDERS = env.bool('WHITENOISE_USE_FINDERS', default=True)


# Function used by WhiteNoise to add headers to static file responses.
def _whitenoise_add_security_headers(headers, path, url):
    # Build CSP parts from settings
    cdns = [s for s in env('CSP_TRUSTED_CDNS', default='').split(',') if s]
    payments = [s for s in env('CSP_PAYMENT_GATEWAYS', default='').split(',') if s]

    script_src = "'self' 'unsafe-inline'"
    if cdns or payments:
        script_src = "'self' 'unsafe-inline' " + ' '.join(cdns + payments)
    style_src = "'self' 'unsafe-inline'"
    if cdns:
        style_src = "'self' 'unsafe-inline' " + ' '.join(cdns)
    img_src = "'self' data:"
    connect_src = "'self'"
    if payments:
        connect_src = "'self' " + ' '.join(payments)
    # Allow framing from trusted cdns/payments and specific external hosts (e.g. download.mql5.com)
    frame_src = "'self'"
    if cdns or payments:
        frame_src = "'self' " + ' '.join(cdns + payments)
    # allow known external download host used by platform links
    if "https://download.mql5.com" not in (cdns + payments):
        frame_src = frame_src + " https://download.mql5.com"

    # In DEBUG allow inline for local development (matches middleware behaviour)
    if DEBUG:
        script_src = "'self' 'unsafe-inline' 'unsafe-eval' " + ((' '.join(cdns + payments)) if (cdns or payments) else '')
        style_src = "'self' 'unsafe-inline' " + ((' '.join(cdns)) if cdns else '')

    csp_parts = [
        "default-src 'self'",
        f"script-src {script_src}",
        f"style-src {style_src}",
        f"img-src {img_src}",
        f"frame-src {frame_src}",
        f"connect-src {connect_src}",
        "object-src 'none'",
        "base-uri 'none'",
    ]
    csp_value = '; '.join([p for p in csp_parts if p]) + ';'

    # Set headers using wsgiref.headers.Headers API
    try:
        # headers is a wsgiref.headers.Headers object; use add_header for compatibility
        headers.add_header('Content-Security-Policy', csp_value)
        headers.add_header('X-Content-Type-Options', 'nosniff')
        headers.add_header('Referrer-Policy', 'same-origin')
        headers.add_header('X-Frame-Options', 'SAMEORIGIN')
        # Permissions policy to restrict powerful browser features
        permissions_policy = "geolocation=(), camera=(), microphone=(), payment=()"
        headers.add_header('Permissions-Policy', permissions_policy)
        # Legacy header for older browsers
        headers.add_header('Feature-Policy', permissions_policy)
        # Cross-origin isolation headers: only in production and when not exempt
        coep_exempt = [s for s in env('COEP_EXEMPT_PATHS', default='').split(',') if s]
        # 'path' is the static file path; if it's exempt, skip COEP/CORP
        if (not DEBUG) and not any(path.startswith(p) or url.startswith(p) for p in coep_exempt):
            headers.add_header('Cross-Origin-Embedder-Policy', 'same-origin')
            headers.add_header('Cross-Origin-Resource-Policy', 'same-site')
        # Build HSTS header from SECURE_HSTS settings when running in production
        hsts_seconds = getattr(sys.modules.get('brokerBackend.settings'), 'SECURE_HSTS_SECONDS', None)
        hsts_seconds = hsts_seconds if hsts_seconds is not None else (31536000 if not DEBUG else 0)
        if (not DEBUG) and hsts_seconds:
            hsts_parts = [f"max-age={int(hsts_seconds)}"]
            if getattr(sys.modules.get('brokerBackend.settings'), 'SECURE_HSTS_INCLUDE_SUBDOMAINS', not DEBUG):
                hsts_parts.append('includeSubDomains')
            if getattr(sys.modules.get('brokerBackend.settings'), 'SECURE_HSTS_PRELOAD', not DEBUG):
                hsts_parts.append('preload')
            headers.add_header('Strict-Transport-Security', '; '.join(hsts_parts))
    except Exception:
        # Fallback for dict-like headers
        headers['Content-Security-Policy'] = csp_value
        headers['X-Content-Type-Options'] = 'nosniff'
        headers['Referrer-Policy'] = 'same-origin'
        headers['X-Frame-Options'] = 'SAMEORIGIN'
        # Permissions policy fallback
        permissions_policy = "geolocation=(), camera=(), microphone=(), payment=()"
        headers['Permissions-Policy'] = permissions_policy
        headers['Feature-Policy'] = permissions_policy
        # Cross-origin isolation fallback: only in production and when not exempt
        coep_exempt = [s for s in env('COEP_EXEMPT_PATHS', default='').split(',') if s]
        if (not DEBUG) and not any(path.startswith(p) or url.startswith(p) for p in coep_exempt):
            headers['Cross-Origin-Embedder-Policy'] = 'same-origin'
            headers['Cross-Origin-Resource-Policy'] = 'same-site'
        hsts_seconds = getattr(sys.modules.get('brokerBackend.settings'), 'SECURE_HSTS_SECONDS', None)
        hsts_seconds = hsts_seconds if hsts_seconds is not None else (31536000 if not DEBUG else 0)
        if (not DEBUG) and hsts_seconds:
            hsts_parts = [f"max-age={int(hsts_seconds)}"]
            if getattr(sys.modules.get('brokerBackend.settings'), 'SECURE_HSTS_INCLUDE_SUBDOMAINS', not DEBUG):
                hsts_parts.append('includeSubDomains')
            if getattr(sys.modules.get('brokerBackend.settings'), 'SECURE_HSTS_PRELOAD', not DEBUG):
                hsts_parts.append('preload')
            headers['Strict-Transport-Security'] = '; '.join(hsts_parts)


# Register the function with WhiteNoise
WHITENOISE_ADD_HEADERS_FUNCTION = _whitenoise_add_security_headers

# Ensure the static directory exists at host time
static_dir = os.path.join(BASE_DIR, 'static')
if not os.path.exists(static_dir):
    os.makedirs(static_dir)

# Ensure logs directory exists
LOG_DIR = os.path.join(BASE_DIR, 'logs')
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

ERROR_LOG_FILE = os.path.join(LOG_DIR, 'errors.log')
ABUSE_LOG_FILE = os.path.join(LOG_DIR, 'abuse.log')


# Windows-safe TimedRotatingFileHandler
# TimedRotatingFileHandler uses os.rename during rotation which can raise
# PermissionError on Windows if another process has the file open. Provide a
# small subclass that falls back to copying+truncating the source file when
# rename fails so the application doesn't crash during rollover.
import logging.handlers


class SafeTimedRotatingFileHandler(logging.handlers.TimedRotatingFileHandler):
    """TimedRotatingFileHandler that tolerates PermissionError on Windows

    If os.rename fails (commonly WinError 32: file used by another process),
    we attempt to copy the file to the destination and then truncate the
    original file so rotation still produces a backup without raising.
    """

    def rotate(self, source, dest):
        try:
            super().rotate(source, dest)
        except PermissionError:
            try:
                # Try a safe copy to create the rotated file
                import shutil
                shutil.copy2(source, dest)
                # Truncate the source file to emulate rotation
                # Preserve encoding handling by opening in text mode
                try:
                    with open(source, 'w', encoding=getattr(self, 'encoding', 'utf8')):
                        pass
                except Exception:
                    # Best-effort: if truncation fails, ignore and continue
                    pass
            except Exception:
                # Last-resort: try os.replace which may succeed in some cases
                try:
                    os.replace(source, dest)
                except Exception:
                    # Give up silently to avoid crashing the application thread
                    pass


class SafeRotatingFileHandler(logging.handlers.RotatingFileHandler):
    """RotatingFileHandler that tolerates PermissionError on Windows.

    If os.rename fails during rotation (WinError 32), copy+truncate is attempted
    to create a backup without raising an exception.
    """

    def rotate(self, source, dest):
        try:
            super().rotate(source, dest)
        except PermissionError:
            try:
                import shutil
                shutil.copy2(source, dest)
                try:
                    with open(source, 'w', encoding=getattr(self, 'encoding', 'utf8')):
                        pass
                except Exception:
                    pass
            except Exception:
                try:
                    os.replace(source, dest)
                except Exception:
                    pass


# Static file serving settings
STATIC_HOST = '' if DEBUG else 'http://static.example.com'

# Disable caching for development
if DEBUG:
    # Disable browser caching for development
    STATICFILES_STORAGE = 'django.contrib.staticfiles.storage.StaticFilesStorage'
    # Add cache-busting for development
    USE_ETAGS = False

# Static Files Finders
STATICFILES_FINDERS = [
    'django.contrib.staticfiles.finders.FileSystemFinder',
    'django.contrib.staticfiles.finders.AppDirectoriesFinder',
]
SERVE_STATIC_FILES = True

# Media Files
MEDIA_URL = '/media/'
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')

# Default primary key field type
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# CORS and CSRF
# Use env flag to control wide-open CORS; default to False in production
CORS_ALLOW_ALL_ORIGINS = env.bool('CORS_ALLOW_ALL_ORIGINS', default=False)
CORS_ALLOW_CREDENTIALS = env.bool('CORS_ALLOW_CREDENTIALS', default=True)
CORS_ALLOWED_ORIGINS = [
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    "http://admin.localhost:8000",
    "http://client.localhost:8000",
    "https://hi5trader.com",
    "http://hi5trader.com",
    "https://www.hi5trader.com",
    "http://www.hi5trader.com",
    "https://admin.hi5trader.com",
    "http://admin.hi5trader.com",
    "https://client.hi5trader.com",
    "http://client.hi5trader.com",
    # Allow CheezePay checkout origin for redirects/iframe/connect
    "https://checkout.cheezepay.com",
    # Use host-only origin for the Cheezeepay API (no path)
    "https://api-cheezeepay-india.cheezeebit.com"
]

CORS_ALLOW_METHODS = [
    'DELETE',
    'GET',
    'OPTIONS',
    'PATCH',
    'POST',
    'PUT',
]

CORS_ALLOW_HEADERS = [
    'accept',
    'accept-encoding',
    'authorization',
    'content-type',
    'dnt',
    'origin',
    'user-agent',
    'x-csrftoken',
    'x-requested-with',
]

CSRF_TRUSTED_ORIGINS = [
    'http://localhost:8000',
    'http://admin.localhost:8000',
    'http://client.localhost:8000',
    'http://www.localhost:8000',
    'https://hi5trader.com',
    'http://hi5trader.com',
    'https://www.hi5trader.com',
    'http://www.hi5trader.com',
    'https://admin.hi5trader.com',
    'http://admin.hi5trader.com',
    'https://client.hi5trader.com',
    'http://client.hi5trader.com',
    # Trusted origin for CheezePay callbacks/redirects
    "https://api-cheezeepay-india.cheezeebit.com",
    "https://checkout.cheezepay.com",
    "https://client.hi5trader.com/static/client/page/main.html",
    "https://admin.hi5trader.com/dashboard"
]

# Content Security Policy configuration: lists of trusted CDN hosts and payment gateways
# Set via .env as comma-separated values, e.g. CSP_TRUSTED_CDNS=https://cdn.example.com,https://fonts.example.com
CSP_TRUSTED_CDNS = [s for s in env('CSP_TRUSTED_CDNS', default='').split(',') if s]
CSP_PAYMENT_GATEWAYS = [s for s in env('CSP_PAYMENT_GATEWAYS', default='').split(',') if s]

# Ensure common external widgets are allowed by default (e.g., Tradays calendar widget)
# You can override via the CSP_TRUSTED_CDNS env var if you prefer explicit control.
_TRADAYS_HOST = 'https://www.tradays.com'
if _TRADAYS_HOST not in CSP_TRUSTED_CDNS:
    CSP_TRUSTED_CDNS.append(_TRADAYS_HOST)

# Ensure CheezePay payment/checkout host is allowed by default so
# frame-src/connect-src for payments permit CheezePay flows even when
# env vars are not set. If you prefer to configure via .env, remove
# these defaults and set `CSP_PAYMENT_GATEWAYS` / `CSP_TRUSTED_CDNS`.
_CHEEZEPAY_HOST = "https://api-cheezeepay-india.cheezeebit.com"
if _CHEEZEPAY_HOST not in CSP_PAYMENT_GATEWAYS:
    CSP_PAYMENT_GATEWAYS.append(_CHEEZEPAY_HOST)
if _CHEEZEPAY_HOST not in CSP_TRUSTED_CDNS:
    CSP_TRUSTED_CDNS.append(_CHEEZEPAY_HOST)

CSRF_COOKIE_DOMAIN = '.localhost'  # Allow subdomains to access CSRF token
CSRF_USE_SESSIONS = False  # Store CSRF token in cookie instead of session
CSRF_COOKIE_HTTPONLY = False  # Allow JavaScript to access CSRF token
# For credentialed cross-origin requests (cookies/auth headers) set SameSite=None
# Note: browsers require Secure cookies when SameSite=None; ensure HTTPS in production.
CSRF_COOKIE_SAMESITE = 'None'
SESSION_COOKIE_SAMESITE = 'None'

# Expose Authorization and CSRF headers to the browser when needed
# (useful if the client needs to read headers returned by the API)
CORS_EXPOSE_HEADERS = [
    'Authorization',
    'Content-Type',
    'X-CSRFToken',
]

# Auth
AUTH_USER_MODEL = 'adminPanel.CustomUser'

# REST Framework
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'adminPanel.authentication.BlacklistCheckingJWTAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
    'DEFAULT_PARSER_CLASSES': [
        'rest_framework.parsers.JSONParser',
        'rest_framework.parsers.FormParser',
        'rest_framework.parsers.MultiPartParser'
    ],
    'UNAUTHENTICATED_USER': None,
    'DEFAULT_RENDERER_CLASSES': [
        'rest_framework.renderers.JSONRenderer',
    ],
    # Throttling - protect against automated abuse and endpoint fuzzing
    'DEFAULT_THROTTLE_CLASSES': [
        'rest_framework.throttling.AnonRateThrottle',
        'rest_framework.throttling.UserRateThrottle',
    ],
    'DEFAULT_THROTTLE_RATES': {
        # Tune these rates for your deployment (examples here)
        'anon': env('DRF_THROTTLE_ANON', default='100/day'),
        'user': env('DRF_THROTTLE_USER', default='1000/day'),
    },
    'EXCEPTION_HANDLER': 'rest_framework.views.exception_handler'
}

# URLs that don't require authentication
PUBLIC_PATHS = [
    '/admin/login/',
    '/client/login/',
    'client/api/login/',
    '/api/login/',
    '/api/verify-otp/',
    '/api/resend-login-otp/',
    '/api/login-otp-status/',
    '/api/status/',
    '/api/csrf/',
    '/api/signup/',
    '/static/',
    '/.well-known/',
    '/favicon.ico',
    '/admin/static/',
    '/client/static/',
    '/static/admin/',
    '/static/client/',
    '/static/shared/',
    '/static/admin/login.html',
    '/static/client/login.html',
    '/static/client/index.html',
    '/index.html',
]

# ============================
# COOKIE AUTO-CLEAR CONFIGURATION (SINGLE SOURCE OF TRUTH)
# ============================
COOKIE_AUTO_CLEAR_CONFIG = {
    'enabled': True,
    'access_token_lifetime': 3600,                     # 5 seconds (in seconds)
    'refresh_token_lifetime': 3600,                    # 1 day (in seconds)
    'session_timeout': 1800,                            # 30 mins
    'remember_me_access_lifetime': 604800,              # 7 days
    'remember_me_refresh_lifetime': 2592000,            # 30 days
}

# ============================
# SIMPLE JWT - Derives from COOKIE_AUTO_CLEAR_CONFIG
# ============================
from datetime import timedelta, datetime, timezone

SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(seconds=COOKIE_AUTO_CLEAR_CONFIG['access_token_lifetime']),
    'REFRESH_TOKEN_LIFETIME': timedelta(seconds=COOKIE_AUTO_CLEAR_CONFIG['refresh_token_lifetime']),
    'ROTATE_REFRESH_TOKENS': True,
    'BLACKLIST_AFTER_ROTATION': True,
    'UPDATE_LAST_LOGIN': True,
    'ALGORITHM': 'HS512',
    'SIGNING_KEY': SECRET_KEY,
    'AUTH_HEADER_TYPES': ('Bearer',),
    'AUTH_HEADER_NAME': 'HTTP_AUTHORIZATION',
    'USER_ID_FIELD': 'id',
    'USER_ID_CLAIM': 'user_id',
    'AUTH_TOKEN_CLASSES': ('rest_framework_simplejwt.tokens.AccessToken',),
    'TOKEN_TYPE_CLAIM': 'token_type',
}

# Allow switching algorithm via env. If using RSA (RS*), load PEM files into
# SIMPLE_JWT['SIGNING_KEY'] (private) and SIMPLE_JWT['VERIFYING_KEY'] (public).
JWT_ALGORITHM = env('JWT_ALGORITHM', default=SIMPLE_JWT.get('ALGORITHM', 'HS512'))
SIMPLE_JWT['ALGORITHM'] = JWT_ALGORITHM

if JWT_ALGORITHM.upper().startswith('RS'):
    # Paths from env (relative to BASE_DIR) or absolute paths
    jwt_priv_path = env('JWT_PRIVATE_KEY_PATH', default=None)
    jwt_pub_path = env('JWT_PUBLIC_KEY_PATH', default=None)

    def _read_key(path):
        if not path:
            return None
        p = path if os.path.isabs(path) else os.path.join(BASE_DIR, path)
        try:
            with open(p, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception as e:
            logger.exception('Failed to read JWT key file %s: %s', p, e)
            return None

    signing_key = _read_key(jwt_priv_path)
    verifying_key = _read_key(jwt_pub_path)

    # Prefer PEM files when available.
    if signing_key and verifying_key:
        SIMPLE_JWT['SIGNING_KEY'] = signing_key
        SIMPLE_JWT['VERIFYING_KEY'] = verifying_key
    else:
        # Fallback: allow using an HMAC signing key from env for this run only.
        # This switches algorithm to HS512 for compatibility and logs a warning.
        fallback_env_key = env('JWT_SIGNING_KEY', default=None)
        if fallback_env_key:
            # Check optional expiry for the fallback; allow ISO8601 or integer epoch seconds
            fallback_expiry_raw = env('JWT_FALLBACK_EXPIRY', default=None)
            expiry_dt = None
            if fallback_expiry_raw:
                try:
                    if str(fallback_expiry_raw).isdigit():
                        expiry_dt = datetime.fromtimestamp(int(fallback_expiry_raw), tz=timezone.utc)
                    else:
                        expiry_dt = datetime.fromisoformat(str(fallback_expiry_raw))
                        if expiry_dt.tzinfo is None:
                            expiry_dt = expiry_dt.replace(tzinfo=timezone.utc)
                except Exception:
                    logger.warning('Invalid JWT_FALLBACK_EXPIRY format: %s', fallback_expiry_raw)
                    expiry_dt = None

            if expiry_dt and datetime.now(tz=timezone.utc) > expiry_dt:
                raise RuntimeError('JWT fallback key expiry has passed; supply PEM files to use RS* algorithm.')

            logger.warning(
                'JWT_ALGORITHM set to %s but PEM files missing. Falling back to HS512 using JWT_SIGNING_KEY from .env for this run only. Expiry: %s',
                JWT_ALGORITHM,
                expiry_dt.isoformat() if expiry_dt else 'none'
            )
            SIMPLE_JWT['ALGORITHM'] = 'HS512'
            SIMPLE_JWT['SIGNING_KEY'] = fallback_env_key
            SIMPLE_JWT.pop('VERIFYING_KEY', None)
        else:
            raise RuntimeError(
                'JWT_ALGORITHM is RS* but JWT_PRIVATE_KEY_PATH or JWT_PUBLIC_KEY_PATH is missing or unreadable, '
                'and no JWT_SIGNING_KEY is provided in .env. Provide PEM files or set JWT_SIGNING_KEY to use HMAC fallback.'
            )


# Logging
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'filters': {
        'exclude_status': {
            '()': 'brokerBackend.log_filters.ExcludeStatusFilter',
            'status_codes': [200, 302],
        },
        'scrub': {
            '()': 'brokerBackend.log_filters.ScrubFilter',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'stream': sys.stdout,
            'filters': ['exclude_status'],
        },
        'daily_file': {
            '()': 'brokerBackend.settings.SafeTimedRotatingFileHandler',
            'filename': os.path.join(LOG_DIR, 'app.log'),
            'when': 'midnight',
            'backupCount': 30,
            'encoding': 'utf8',
            'level': 'DEBUG',
            'formatter': 'json',
        },
        'abuse_file': {
            '()': 'brokerBackend.settings.SafeRotatingFileHandler',
            'filename': ABUSE_LOG_FILE,
            'maxBytes': 1024*1024,  # 1MB
            'backupCount': 5,
            'level': 'WARNING',
            'formatter': 'abuse_simple',
        },
    },
    'formatters': {
        'standard': {
            'format': '%(asctime)s %(levelname)s %(name)s %(message)s',
            'datefmt': '%Y-%m-%d %H:%M:%S',
        },
        'json': {
            '()': 'brokerBackend.log_formatters.JSONFormatter',
        },
        'abuse_simple': {
            'format': '%(asctime)s %(levelname)s %(name)s %(message)s'
        }
    },
    'root': {
        'handlers': ['console'],
        'level': 'DEBUG',
    },
    'loggers': {
        # Ensure middleware and admin view modules send warnings to abuse_file
        'brokerBackend.middleware': {
            'handlers': ['abuse_file'],
            'level': 'WARNING',
            'propagate': False,
        },
        'adminPanel': {
            'handlers': ['abuse_file'],
            'level': 'WARNING',
            'propagate': False,
        },
        # Server and HTTP libraries: attach console with exclude_status filter
        'django.server': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': False,
        },
        'waitress': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': False,
        },
        'werkzeug': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': False,
        },
        'whitenoise': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': False,
        },
        'access': {
            'handlers': ['daily_file'],
            'level': 'INFO',
            'propagate': False,
        },
    },
}

# Email Configuration (Hostinger SMTP)
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_USE_SSL = False
EMAIL_HOST_USER = 'support@vtindex.com'
EMAIL_HOST_PASSWORD = 'xbeppbkyyetoenag'
DEFAULT_FROM_EMAIL = 'vtindex <support@vtindex.com>'
# Email Configuration (Hostinger SMTP, loaded from .env)
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = env('EMAIL_HOST', default='smtp.gmail.com')
EMAIL_PORT = env.int('EMAIL_PORT', default=587)
EMAIL_USE_TLS = env.bool('EMAIL_USE_TLS', default=True)
EMAIL_USE_SSL = env.bool('EMAIL_USE_SSL', default=False)
EMAIL_HOST_USER = env('EMAIL_HOST_USER', default='support@vtindex.com')
EMAIL_HOST_PASSWORD = env('EMAIL_HOST_PASSWORD', default='xbeppbkyyetoenag')
DEFAULT_FROM_EMAIL = env('DEFAULT_FROM_EMAIL', default='vtindex <support@vtindex.com>')

EMAIL_SEND_DELAY_SECONDS = env.int('EMAIL_SEND_DELAY_SECONDS', default=env.int('EMAIL_SEND_DELAY', default=30))
# Log configured value to help troubleshooting at startup
logger.debug(f'EMAIL_SEND_DELAY_SECONDS: {EMAIL_SEND_DELAY_SECONDS}')

# Server email used as the sender for error emails (ADMINS/handlers and middleware alerts)
SERVER_EMAIL = env('SERVER_EMAIL', default=DEFAULT_FROM_EMAIL)

# API monitoring alert recipients (used by APIMonitoringMiddleware). Can be a
# comma-separated list in .env: API_MONITOR_ALERT_RECIPIENTS=ops@...,sec@...
API_MONITOR_ALERT_RECIPIENTS = [s for s in env('API_MONITOR_ALERT_RECIPIENTS', default='support@vtindex.com,tamizharasan@vtindex.com,iyyanar@vtindex.com').split(',') if s]


# Optional: separate SMTP settings used only for sending reports (overrides EMAIL_* when set)
REPORTS_EMAIL_HOST = env('REPORTS_EMAIL_HOST', default=EMAIL_HOST)
REPORTS_EMAIL_PORT = env.int('REPORTS_EMAIL_PORT', default=EMAIL_PORT)
REPORTS_EMAIL_USE_TLS = env.bool('REPORTS_EMAIL_USE_TLS', default=EMAIL_USE_TLS)
REPORTS_EMAIL_USE_SSL = env.bool('REPORTS_EMAIL_USE_SSL', default=EMAIL_USE_SSL)
REPORTS_EMAIL_HOST_USER = env('REPORTS_EMAIL_HOST_USER', default=EMAIL_HOST_USER)
REPORTS_EMAIL_HOST_PASSWORD = env('REPORTS_EMAIL_HOST_PASSWORD', default=EMAIL_HOST_PASSWORD)
REPORTS_DEFAULT_FROM_EMAIL = env('REPORTS_DEFAULT_FROM_EMAIL', default=DEFAULT_FROM_EMAIL)


#  Hosts
# ROOT_HOSTCONF = 'brokerBackend.hosts'
# DEFAULT_HOST = 'www'
# import socket
# if DEBUG or 'localhost' in socket.gethostname() or '127.0.0.1' in ALLOWED_HOSTS:
#    PARENT_HOST = 'localhost:8000'
# else:
#     PARENT_HOST = 'vtindex.com'
# HOST_PORT = '8000'
# HOST_SCHEME = 'http'

# Hosts
ROOT_HOSTCONF = 'brokerBackend.hosts'
DEFAULT_HOST = 'www'
PARENT_HOST = 'hi5trader.com'
HOST_PORT = '8000'
HOST_SCHEME = 'http'


# Admin Settings
ADMIN_URL = 'admin/'
ADMIN_SITE_HEADER = "CRM Administration"
ADMIN_SITE_TITLE = "CRM Admin Portal"

# Authentication Settings
LOGIN_URL = '/login/'
LOGIN_REDIRECT_URL = '/dashboard/'
LOGOUT_REDIRECT_URL = '/login/'

# Security Settings
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
# Allow overriding via env; default to redirecting when not in DEBUG
SECURE_SSL_REDIRECT = env.bool('SECURE_SSL_REDIRECT', default=not DEBUG)  # Redirect HTTP to HTTPS in production
SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_HTTPONLY = True

COOKIE_SECURE_FLAG_OVERRIDE = env.bool('COOKIE_SECURE_FLAG_OVERRIDE', default=False)

# Comma-separated list of IPs that are allowed to access admin endpoints when
# the request is not coming from the `admin.` subdomain or localhost.
ADMIN_ALLOWED_IPS = [s for s in env('ADMIN_ALLOWED_IPS', default='').split(',') if s]

# Trust the reverse proxy's forwarded proto header so Django knows when requests
# are already HTTPS (required when using IIS/ARR or other reverse proxies).
# This prevents an HTTP->HTTPS redirect loop when the proxy forwards
# X-Forwarded-Proto: https but Django sees the connection as plain HTTP.
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

# HTTP Strict Transport Security (HSTS): enforce HTTPS for browsers
# In production set SECURE_HSTS_SECONDS to a large value (e.g. 31536000)
# and ensure `SECURE_SSL_REDIRECT` is True and `DEBUG` is False.
SECURE_HSTS_SECONDS = env.int('SECURE_HSTS_SECONDS', default=31536000)
SECURE_HSTS_INCLUDE_SUBDOMAINS = env.bool('SECURE_HSTS_INCLUDE_SUBDOMAINS', default=not DEBUG)
SECURE_HSTS_PRELOAD = env.bool('SECURE_HSTS_PRELOAD', default=not DEBUG)

# Paths that should be exempt from Cross-Origin-Embedder-Policy/CORP.
# Comma-separated in .env, e.g. COEP_EXEMPT_PATHS=/embed/,/public/iframe/
COEP_EXEMPT_PATHS = [s for s in env('COEP_EXEMPT_PATHS', default='').split(',') if s]

# Authentication backends
AUTHENTICATION_BACKENDS = [
    'django.contrib.auth.backends.ModelBackend',
]

# Load CheesePay Configurations
CHEESEPAY_CONFIG = {
    "MERCHANT_ID": env("CHEESEPAY_MERCHANT_ID"),
    "APP_ID": env("CHEESEPAY_APP_ID"),
    "PAYIN_URL": env("CHEESEPAY_PAYIN_URL"),
}

# Debugging the environment variables
logger.debug(f'DJANGO_SECRET_KEY: {env("DJANGO_SECRET_KEY", default="Not Set")}')
logger.debug(f'ACCESS_TOKEN_LIFETIME: {env.int("ACCESS_TOKEN_LIFETIME", default=7)}')

# Channels Configuration for WebSocket support
CHANNEL_LAYERS = {
    'default': {
        'BACKEND': 'channels.layers.InMemoryChannelLayer',
    },
}

# WebSocket Configuration
# Add WebSocket allowed origins
WEBSOCKET_ALLOWED_ORIGINS = [
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    "http://admin.localhost:8000",
    "http://client.localhost:8000",
    "https://hi5trader.com",
    "http://hi5trader.com",
    "https://www.hi5trader.com",
    "http://www.hi5trader.com",
    "https://admin.hi5trader.com",
    "https://admin.hi5trader.com/dashboard",
    "http://admin.hi5trader.com",
    "https://client.hi5trader.com",
    "https://client.hi5trader.com/static/client/page/main.html",
    "http://client.hi5trader.com", # Add your production HTTPS domain
]

# Optional: Redis Channel Layer (for production)
# Uncomment below and comment out the InMemoryChannelLayer for production use
# CHANNEL_LAYERS = {
#     'default': {
#         'BACKEND': 'channels_redis.core.RedisChannelLayer',
#         'CONFIG': {
#             "hosts": [('127.0.0.1', 6379)],
#         },
#     },
# }

# Celery Configuration
CELERY_BROKER_URL = env('CELERY_BROKER_URL', default='redis://localhost:6379/0')
CELERY_RESULT_BACKEND = env('CELERY_RESULT_BACKEND', default='redis://localhost:6379/0')

# Commission Webhook Security
COMMISSION_WEBHOOK_TOKEN = env('COMMISSION_WEBHOOK_TOKEN', default='change-this-token-in-production')

# Optional: comma-separated list of IPs allowed to call commission/webhook endpoints
COMMISSION_WEBHOOK_ALLOWED_IPS = [s for s in env('COMMISSION_WEBHOOK_ALLOWED_IPS', default='').split(',') if s]

# Comma-separated list of webhook paths to protect with shared-secret header or IP whitelist
COMMISSION_WEBHOOK_PATHS = [s for s in env('COMMISSION_WEBHOOK_PATHS', default='/api/v1/commission-creation/').split(',') if s]


# Celery task serialization
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'
CELERY_ACCEPT_CONTENT = ['json']
CELERY_TIMEZONE = 'UTC'
CELERY_ENABLE_UTC = True

# Celery Beat Schedule - REPLACED WITH BACKGROUND THREADING
# The monthly reports are now handled by background threading similar to commission sync
# See adminPanel.monthly_reports_thread for the implementation
# 
# Original Celery Beat schedule has been replaced with:
# - Background thread that checks every hour for the 1st of the month
# - Automatic execution of monthly report generation at 2:00 AM equivalent
# - Backup retry mechanism at 4:00 AM equivalent for failed emails
# 
# Benefits of background threading approach:
# - No external dependencies (Redis/RabbitMQ)
# - Simpler deployment and maintenance
# - Consistent with commission sync implementation
# - Better error handling and logging
#
# To manually trigger monthly reports, use:
# from adminPanel.monthly_reports_thread import monthly_reports_thread
# monthly_reports_thread.force_run_monthly_reports("2025-01")  # Optional month parameter

# Legacy Celery Beat configuration (commented out):
# from celery.schedules import crontab
# CELERY_BEAT_SCHEDULE = {
#     'generate-and-email-monthly-reports': {
#         'task': 'generate_and_email_monthly_reports',
#         'schedule': crontab(hour=2, minute=0, day_of_month=1),
#         'options': {
#             'description': 'Generate monthly trade reports for all users and EMAIL them automatically'
#         }
#     },
#     'retry-failed-monthly-report-emails': {
#         'task': 'generate_and_email_monthly_reports',
#         'schedule': crontab(hour=4, minute=0, day_of_month=1),
#         'kwargs': {'force_email': True},
#         'options': {
#             'description': 'Retry any failed monthly report email sends'
#         }
#     },
# }

# Celery Beat Schedule (Periodic Tasks)
from celery.schedules import crontab

CELERY_BEAT_SCHEDULE = {
    'cleanup-old-notifications-daily': {
        'task': 'cleanup_old_notifications',
        'schedule': crontab(hour=0, minute=0),  # Run every day at midnight
        'args': (7,),  # Delete notifications read more than 7 days ago
    },
    # Add other periodic tasks here as needed
}




# ============================
# COOKIE AUTO-CLEAR CONFIGURATION
# ============================
# Backend-controlled cookie expiration and auto-clear settings
# All time values are in seconds
# COOKIE_AUTO_CLEAR_CONFIG = {
#     'enabled': True,                                    # Enable/disable auto-clear functionality
#     'access_token_lifetime': 60,                       # Access token: 1 minute (60 seconds)
#     'refresh_token_lifetime': 2592000,                  # Refresh token: 30 days (2592000 seconds)
#     'session_timeout': 1800,                            # Session idle timeout: 30 mins (1800 seconds)
#     'remember_me_access_lifetime': 604800,              # Remember-me access: 7 days (604800 seconds)
#     'remember_me_refresh_lifetime': 2592000,            # Remember-me refresh: 30 days (2592000 seconds)
# }
# 
# Configuration Guide:
# - access_token_lifetime: Time until access token expires (e.g., 1 hour = 3600 seconds)
# - refresh_token_lifetime: Time until refresh token expires (e.g., 30 days = 2592000 seconds)
# - session_timeout: Idle session timeout (e.g., 30 mins = 1800 seconds)
# - remember_me_access_lifetime: Access token lifetime when "Remember Me" is enabled
# - remember_me_refresh_lifetime: Refresh token lifetime when "Remember Me" is enabled
#
# IMPORTANT: Changing these values will:
# 1. Automatically apply to all new login sessions
# 2. Require browser to store cookies only for the configured duration
# 3. Clear cookies automatically after the specified time expires
#
# Note: Browser respects max_age; server-side cleanup happens during requests

