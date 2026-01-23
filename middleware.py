from django.http import HttpResponseBadRequest, HttpResponseForbidden
from django.shortcuts import redirect
from django.conf import settings
from django.urls import reverse
from django.contrib.auth.views import redirect_to_login
from django.utils.deprecation import MiddlewareMixin
import logging
import time
from django.core.cache import cache
from django.core.mail import send_mail, EmailMessage
from . import alerting

logger = logging.getLogger(__name__)


class GlobalSecurityHeadersMiddleware(MiddlewareMixin):
    """Ensure a minimal set of security headers are present on every response.

    This middleware is applied very early in the stack so that responses
    returned by earlier middleware still get security headers (404s, rejects,
    probes, etc.). It only sets defaults when a header is not already present.
    """

    def process_response(self, request, response):
        try:
            response.setdefault('X-Content-Type-Options', 'nosniff')
            response.setdefault('X-Frame-Options', 'SAMEORIGIN')
            response.setdefault('X-XSS-Protection', '1; mode=block')
            response.setdefault('Referrer-Policy', 'same-origin')
            # Minimal fallback CSP to ensure a policy exists for clients that
            # rely on it; existing middleware/settings may provide a stronger CSP.
            if not response.get('Content-Security-Policy'):
                response['Content-Security-Policy'] = "default-src 'self';"
        except Exception:
            logger.exception('Error while applying global security headers')
        return response


def _effective_cdns():
    """Return the configured CSP_TRUSTED_CDNS plus a small set of common external CDNs

    This ensures fonts/styles/scripts from common providers (Google Fonts, cdnjs,
    Cloudflare Insights) are allowed by the middleware-generated CSP without
    requiring every deployment to set `CSP_TRUSTED_CDNS` explicitly.
    """
    cdns = list(getattr(settings, 'CSP_TRUSTED_CDNS', []) or [])
    defaults = [
        'https://cdnjs.cloudflare.com',
        'https://fonts.googleapis.com',
        'https://fonts.gstatic.com',
        'https://static.cloudflareinsights.com',
        'https://www.tradays.com',
    ]
    for d in defaults:
        if d not in cdns:
            cdns.append(d)
    return cdns

class NoCacheMiddleware(MiddlewareMixin):
    """
    Middleware to disable caching for development purposes.
    This will force browsers to always fetch fresh content.
    """
    
    def process_response(self, request, response):
        # Apply cache-busting headers during development
        if settings.DEBUG:
            # Do not clutter logs for known automated probes (requests for .env, /cgi-bin/, etc.)
            path = (request.path or '').lower()
            probe_patterns = ['.env', '/cgi-bin/']
            if any(pat in path for pat in probe_patterns):
                # Return the response unchanged and avoid log noise
                return response

            # Apply to all other responses, not just static files
            response['Cache-Control'] = 'no-cache, no-store, must-revalidate, max-age=0'
            response['Pragma'] = 'no-cache'
            response['Expires'] = '0'

            # Remove ETag to prevent 304 responses
            if 'ETag' in response:
                del response['ETag']
            # Remove Last-Modified to prevent 304 responses  
            if 'Last-Modified' in response:
                del response['Last-Modified']
        
        return response

    def process_request(self, request):
        """
        Early-return 404 for common automated probes (requests for .env, cgi-bin, etc.)
        to reduce log noise and avoid running other middleware for malicious scans.
        """
        path = (request.path or '').lower()

        # Patterns to block quietly
        suspicious_patterns = ['.env', '/cgi-bin/', '/.env', '/backend/.env', '/src/.env', '/base/.env', '/core/.env']

        if any(pat in path for pat in suspicious_patterns):
            # Return a simple 404 Not Found without additional processing
            from django.http import HttpResponseNotFound
            return HttpResponseNotFound()

        return None

class SubdomainMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Skip subdomain check for public paths
        if (request.path.startswith('/static/') or 
            request.path.startswith('/.well-known/') or 
            request.path == '/favicon.ico' or
            any(request.path.startswith(path) for path in getattr(settings, 'PUBLIC_PATHS', []))):
            return self.get_response(request)

        host = request.META.get('HTTP_HOST', '')
        
        # Handle localhost and IP addresses for development
        if host.startswith('127.0.0.1') or host.startswith('localhost'):
            request.subdomain = 'localhost'
            return self.get_response(request)
            
        parts = host.split('.')
        
        if len(parts) <= 2:
            request.subdomain = 'www'
        else:
            subdomain = parts[0]
            if subdomain not in ['www', 'admin', 'client', 'localhost']:
                return HttpResponseBadRequest("Invalid subdomain")
            request.subdomain = subdomain
        return self.get_response(request)

class AdminHostRestrictMiddleware:
    """Block access to admin endpoints unless coming from the admin host or an allowed IP."""
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        host = request.META.get('HTTP_HOST', '')
        path = (request.path or '')

        # Only enforce for admin-like paths; skip static/public paths
        admin_like = (
            path.startswith('/admin/') or
            path.startswith('/admin-api/') or
            path.startswith('/api/admin/') or
            path.startswith('/admaan/')
        )

        if not admin_like:
            return self.get_response(request)

        # Allow localhost / development hosts
        if host.startswith('localhost') or host.startswith('127.0.0.1'):
            return self.get_response(request)

        # Allow requests from configured admin subdomain
        if host.split(':')[0].startswith('admin.'):
            return self.get_response(request)

        # Allow whitelisted IPs from settings.ADMIN_ALLOWED_IPS
        try:
            from django.conf import settings
            allowed = getattr(settings, 'ADMIN_ALLOWED_IPS', []) or []
        except Exception:
            allowed = []
        ip = request.META.get('REMOTE_ADDR')
        if ip and ip in allowed:
            return self.get_response(request)

        return HttpResponseForbidden('Admin endpoints are restricted')

class AdminAPIEnforceMiddleware:
    """Enforce JWT authentication and admin role for admin API endpoints.

    This middleware ensures endpoints under `/api/admin/`, `/admin-api/` and
    similar admin API paths require a valid JWT and that the user has admin
    or manager privileges. It logs unauthorized attempts.
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        path = (request.path or '')

        # Allow CORS preflight requests to pass through without authentication
        if request.method == 'OPTIONS':
            return self.get_response(request)
        admin_api_like = (
            path.startswith('/api/admin/') or
            path.startswith('/admin-api/') or
            path.startswith('/api/admin')
        )

        if not admin_api_like:
            return self.get_response(request)

        # Try to authenticate using SimpleJWT
        try:
            from rest_framework_simplejwt.authentication import JWTAuthentication
            jwt_auth = JWTAuthentication()
            # If Authorization header not present, try common cookie names and inject
            if not request.headers.get('Authorization'):
                for ck in ('accessToken', 'jwt_token', 'access_token', 'token'):
                    try:
                        v = request.COOKIES.get(ck)
                    except Exception:
                        v = None
                    if v:
                        request.META['HTTP_AUTHORIZATION'] = f'Bearer {v}'
                        break
            auth_result = jwt_auth.authenticate(request)
            if auth_result is None:
                ip = request.META.get('REMOTE_ADDR')
                logger.warning('Unauthorized admin API access attempt %s from %s', path, ip)
                return HttpResponseForbidden('Authentication required')
            user, token = auth_result
            request.user = user
            request.auth = token

            if not getattr(user, 'manager_admin_status', None) in ['Admin', 'Manager']:
                ip = request.META.get('REMOTE_ADDR')
                logger.warning('Forbidden admin API access by %s (%s) to %s', getattr(user, 'email', 'unknown'), ip, path)
                return HttpResponseForbidden('Admin privileges required')

        except Exception as exc:
            logger.exception('Admin API auth error: %s', exc)
            return HttpResponseForbidden('Authentication error')

        return self.get_response(request)


class RequestAbuseLoggingMiddleware:
    """Log suspicious or blocked requests (403, 429) for monitoring.

    This middleware writes concise warnings for blocked or rate-limited
    requests including IP, method and path to aid investigation.
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        try:
            status = getattr(response, 'status_code', None)
            if status in (403, 429):
                ip = request.META.get('REMOTE_ADDR')
                user = getattr(request, 'user', None)
                user_repr = getattr(user, 'email', str(user)) if user else 'anonymous'
                logger.warning('Blocked request: ip=%s user=%s method=%s path=%s status=%s',
                               ip, user_repr, request.method, request.path, status)
        except Exception:
            # Ensure logging middleware never raises
            logger.exception('Error while logging blocked request')

        return response


class AdminAuthenticationMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Skip auth check for non-admin paths
        if not (request.path.startswith('/admin/') or request.path.startswith('/api/admin/') or 
                request.path.startswith('/admin-api/') or request.path.startswith('/ib-user/') or
                request.path.startswith('/manager/dashboard/') or request.path.startswith('/dashboard/')):
            return self.get_response(request)

        # Skip auth check for public paths and static files
        if (request.path.startswith('/static/') or 
            request.path.startswith('/.well-known/') or 
            request.path == '/favicon.ico' or
            request.path.startswith('/client/') or  # Skip all client paths - they handle their own auth
            any(request.path.startswith(path) for path in settings.PUBLIC_PATHS)):
            return self.get_response(request)

        # Skip auth check for login and authentication endpoints
        if request.path in ['/login/', '/api/login/', '/api/token/refresh/', '/api/logout/', '/api/validate-token/']:
            return self.get_response(request)

        # For API endpoints and dashboard endpoints, let DRF handle authentication
        if (request.path.startswith('/api/') or request.path.startswith('/admin-api/') or 
            request.path.startswith('/ib-user/') or request.path.startswith('/adminPanel/api/') or
            request.path.startswith('/manager/dashboard/') or request.path.startswith('/dashboard/') or
            request.path.startswith('/admin/dashboard/')):
            return self.get_response(request)

        # For other admin paths, require authentication
        # Get JWT token from Authorization header (for non-API admin paths)
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            if request.headers.get('Accept') == 'application/json':
                return HttpResponseForbidden({'error': 'Authentication required'})
            return redirect_to_login(next=request.get_full_path(), login_url=settings.LOGIN_URL)

        # Validate JWT from Authorization header for non-API admin paths
        # Use DRF SimpleJWT authentication to populate request.user and request.auth
        try:
            from rest_framework_simplejwt.authentication import JWTAuthentication
            jwt_auth = JWTAuthentication()
            auth_result = jwt_auth.authenticate(request)
            if auth_result is None:
                return HttpResponseForbidden({'error': 'Invalid or expired token'})
            user, token = auth_result
            request.user = user
            request.auth = token
        except Exception:
            return HttpResponseForbidden({'error': 'Invalid or expired token'})

        # Check for admin/manager privileges
        if not request.user.manager_admin_status in ['Admin', 'Manager']:
            return HttpResponseForbidden({'error': 'Admin privileges required'})
            
        return self.get_response(request)

class EarlyAPIAuthMiddleware:
    """Reject unauthenticated API requests early.

    Runs for API-like paths (starting with `/api/`) and rejects requests
    that are not authenticated via session or JWT, except for paths
    listed in `settings.PUBLIC_PATHS` or other explicit exemptions.
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        path = (request.path or '')

        # Only enforce for API root paths
        if not (path.startswith('/api/') or path.startswith('/client/api/') or path.startswith('/admin-api/')):
            return self.get_response(request)

        # Allow public/exempt paths
        public_paths = getattr(settings, 'PUBLIC_PATHS', []) or []
        for p in public_paths:
            if path.startswith(p):
                return self.get_response(request)

        # Allow static and well-known
        if path.startswith('/static/') or path.startswith('/.well-known/') or path == '/favicon.ico':
            return self.get_response(request)

        # Exempt common client auth endpoints (login/signup/validate/otp) from early rejection
        # so the frontend can obtain/verify tokens and OTPs without already being authenticated.
        if (
            path.startswith('/client/api/login') or
            path.startswith('/client/api/signup') or
            path.startswith('/client/api/validate-token') or
            path.startswith('/client/api/verify-otp') or
            path.startswith('/api/send-reset-otp/') or
            path.startswith('/api/reset-password/confirm/') or
            path.startswith('/api/reset-password/') or
            path.startswith('/client/api/resend-otp') or
            path.startswith('/client/api/resend-login-otp') or
            path.startswith('/api/resend-login-otp') or
            path.startswith('/client/api/send-reset-otp/') or
            path.startswith('/api/send-signup-otp/') or
            path.startswith('/api/verify-signup-otp/') or
	        path.startswith('/client/api/reset-password/confirm/') or
	        path.startswith('/client/api/reset-password/') or
            path.startswith('/api/oauth/google') or
            path.startswith('/api/oauth/microsoft')
        ):
            return self.get_response(request)

        # If Django AuthenticationMiddleware already set a valid user, allow
        try:
            if hasattr(request, 'user') and request.user.is_authenticated:
                return self.get_response(request)
        except Exception:
            pass

        # Diagnostic logging to help trace credentialed request failures.
        # Mask tokens before logging to avoid leaking secrets.
        try:
            # If no Authorization header present, try common cookie names used by frontend
            # and inject an HTTP_AUTHORIZATION META so DRF SimpleJWT can pick it up.
            auth_header = request.headers.get('Authorization')
            if not auth_header:
                for ck in ('accessToken', 'jwt_token', 'access_token', 'token'):
                    try:
                        val = request.COOKIES.get(ck)
                    except Exception:
                        val = None
                    if val:
                        request.META['HTTP_AUTHORIZATION'] = f'Bearer {val}'
                        auth_header = request.META.get('HTTP_AUTHORIZATION')
                        break
            cookie = request.META.get('HTTP_COOKIE')
            has_cookie = bool(cookie)
            masked = None
            if auth_header and auth_header.startswith('Bearer '):
                tok = auth_header.split(' ', 1)[1]
                masked = f"Bearer {tok[:8]}...{tok[-4:]}"
            else:
                masked = auth_header
            logger.debug('EarlyAPIAuth debug: path=%s method=%s ip=%s has_cookie=%s auth_header=%s',
                         path, request.method, request.META.get('REMOTE_ADDR'), has_cookie, masked)
        except Exception:
            logger.exception('Error while logging EarlyAPIAuth debug info')

        # Try configured DRF authentication classes first (this allows
        # project-custom classes that read JWTs from cookies to succeed).
        try:
            auth_classes = []
            rf = getattr(settings, 'REST_FRAMEWORK', {}) or {}
            for cls_path in rf.get('DEFAULT_AUTHENTICATION_CLASSES', []):
                try:
                    module_path, cls_name = cls_path.rsplit('.', 1)
                    mod = __import__(module_path, fromlist=[cls_name])
                    cls = getattr(mod, cls_name)
                    auth_classes.append(cls)
                except Exception:
                    logger.debug('Could not import auth class %s', cls_path)

            for cls in auth_classes:
                try:
                    inst = cls()
                    auth_result = inst.authenticate(request)
                    if auth_result is not None:
                        user, token = auth_result
                        request.user = user
                        request.auth = token
                        logger.debug('EarlyAPIAuth: authenticated via %s', getattr(cls, '__name__', str(cls)))
                        return self.get_response(request)
                except Exception:
                    logger.exception('Auth class %s raised while authenticating', getattr(cls, '__name__', str(cls)))
        except Exception:
            logger.exception('Error while attempting configured DRF authentication classes')

        # Fallback: try direct SimpleJWT JWTAuthentication (Authorization header)
        try:
            from rest_framework_simplejwt.authentication import JWTAuthentication
            jwt_auth = JWTAuthentication()
            # Ensure Authorization header is available from cookies if present
            if not request.headers.get('Authorization'):
                for ck in ('accessToken', 'jwt_token', 'access_token', 'token'):
                    try:
                        v = request.COOKIES.get(ck)
                    except Exception:
                        v = None
                    if v:
                        request.META['HTTP_AUTHORIZATION'] = f'Bearer {v}'
                        break
            auth_result = jwt_auth.authenticate(request)
            if auth_result is not None:
                user, token = auth_result
                request.user = user
                request.auth = token
                return self.get_response(request)
        except Exception:
            # Fall through to reject
            logger.debug('JWT auth attempt failed or not present for path %s', path)

        # Not authenticated: reject before view logic
        from django.http import JsonResponse
        ip = request.META.get('REMOTE_ADDR')
        logger.warning('Rejected unauthenticated API request %s from %s', path, ip)
        return JsonResponse({'detail': 'Authentication credentials were not provided.'}, status=401)


class WebhookProtectionMiddleware:
    """Protect configured webhook paths by validating a shared secret header or source IP.

    Checks `settings.COMMISSION_WEBHOOK_PATHS` and allows requests that present the
    correct `X-WEBHOOK-TOKEN` header matching `settings.COMMISSION_WEBHOOK_TOKEN`, or
    originate from an IP listed in `settings.COMMISSION_WEBHOOK_ALLOWED_IPS`.
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        path = (request.path or '')
        try:
            from django.conf import settings
            webhook_paths = getattr(settings, 'COMMISSION_WEBHOOK_PATHS', []) or []
            allowed_ips = getattr(settings, 'COMMISSION_WEBHOOK_ALLOWED_IPS', []) or []
            secret = getattr(settings, 'COMMISSION_WEBHOOK_TOKEN', None)
        except Exception:
            webhook_paths = []
            allowed_ips = []
            secret = None

        if not any(path.startswith(p) for p in webhook_paths):
            return self.get_response(request)

        # Allow if request IP is whitelisted
        ip = request.META.get('REMOTE_ADDR')
        if ip and ip in allowed_ips:
            return self.get_response(request)

        # Validate header token
        header_token = request.META.get('HTTP_X_WEBHOOK_TOKEN') or request.headers.get('X-WEBHOOK-TOKEN')
        if secret and header_token and header_token == secret:
            return self.get_response(request)

        # Reject otherwise
        from django.http import JsonResponse
        logger.warning('Rejected webhook call to %s from %s', path, ip)
        return JsonResponse({'detail': 'Invalid webhook credentials'}, status=403)


class ClientCSRFExemptMiddleware(MiddlewareMixin):
    """
    Disable CSRF protection for client API endpoints
    """
    def process_request(self, request):
        # List of paths that should be exempt from CSRF
        csrf_exempt_paths = [
            '/client/api/',
            '/client/login/',
            '/client/signup/',
            '/client/reset-password/',
            '/client/user-info/',
            '/client/recent-transactions/',
            '/client/stats-overview/',
            '/client/validate-token/',
            '/client/user-accounts/',
            '/client/user-demo-accounts/',
            '/client/getmydetails/',
            '/client/user-transactions/',
            '/client/pending-transactions/',
            '/client/user-trading-accounts/',
            '/client/create-trading-account/',
            '/client/create-demo-account/',      
            '/client/create-live-account/', 
            '/client/notifications/',  # Notification endpoints     
            '/api/login/',  # For subdomain access
            '/api/signup/',  # For subdomain access
            '/api/reset-password/',  # For subdomain access
            '/api/user-info/',  # For subdomain access
            '/api/recent-transactions/',  # For subdomain access
            '/api/stats-overview/',  # For subdomain access
            '/api/validate-token/',  # For subdomain access
            '/api/server-settings/',  # Add server settings for admin subdomain
            '/client/cheezepay-notify/',  # CheezePay webhook notification endpoint
            '/client/cheezepay-notify',  # Allow without trailing slash as well
        ]
        
        # Handle both direct and subdomain access
        host = request.META.get('HTTP_HOST', '')
        is_client_subdomain = host.startswith('client.')
        is_admin_subdomain = host.startswith('admin.')
        
        # Check if the request path matches any exempt paths
        if (any(request.path.startswith(path) for path in csrf_exempt_paths) or 
            (is_client_subdomain and request.path.startswith('/api/')) or
            (is_admin_subdomain and request.path.startswith('/api/'))):
            request.csrf_processing_done = True
        
        return None


class AllowIframeMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        # List of trusted domains that are allowed to embed the page in an iframe
        trusted_domains = [
            'https://client.hi5trader.com',
            'https://admin.hi5trader.com',
            'http://admin.localhost:8000',
            'http://client.localhost:8000',
            # Allow CheezePay hosts (host-only, no path)
            'https://checkout.cheezepay.com',
            'https://api-cheezeepay-india.cheezeebit.com',
        ]

        # Add Content-Security-Policy header to control iframe embedding
        csp_value = "frame-ancestors 'self' " + ' '.join(trusted_domains)
        response.headers['Content-Security-Policy'] = csp_value
        
        return response

    def process_response(self, request, response):
        """Ensure security headers are applied to all responses, including errors.

        This mirrors the headers set in __call__ so responses generated
        earlier in the middleware chain (including error handlers) still
        receive the full set of security headers.
        """
        try:
            # Build CSP from settings (include common CDNs by default)
            cdns = _effective_cdns()
            payments = getattr(settings, 'CSP_PAYMENT_GATEWAYS', []) or []

            def join_src(lst):
                return ' '.join(lst) if lst else ''

            script_src = ["'self'", "'unsafe-inline'"] + cdns + payments
            style_src = ["'self'", "'unsafe-inline'"] + cdns
            img_src = ["'self'", 'data:']
            connect_src = ["'self'"] + payments
            frame_src = ["'self'"] + cdns + payments
            if 'https://download.mql5.com' not in frame_src:
                frame_src.append('https://download.mql5.com')
            if 'about:' not in frame_src:
                frame_src.append('about:')
            if 'data:' not in frame_src:
                frame_src.append('data:')

            if settings.DEBUG:
                script_src = ["'self'", "'unsafe-inline'", "'unsafe-eval'"] + cdns + payments
                style_src = ["'self'", "'unsafe-inline'"] + cdns

            csp_parts = [
                "default-src 'self'",
                f"script-src {join_src(script_src)}",
                f"style-src {join_src(style_src)}",
                f"img-src {join_src(img_src)}",
                f"frame-src {join_src(frame_src)}",
                f"connect-src {join_src(connect_src)}",
            ]
            if cdns:
                csp_parts.append(f"font-src {join_src(cdns)}")
            csp_parts.append("object-src 'none'")
            csp_parts.append("base-uri 'none'")

            csp_value = '; '.join([p for p in csp_parts if p]) + ';'

            response.setdefault('Content-Security-Policy', csp_value)
            response.setdefault('X-Content-Type-Options', 'nosniff')
            response.setdefault('Referrer-Policy', 'same-origin')
            response.setdefault('X-Frame-Options', 'SAMEORIGIN')

            permissions_policy = "geolocation=(), camera=(), microphone=(), payment=()"
            response.setdefault('Permissions-Policy', permissions_policy)
            response.setdefault('Feature-Policy', permissions_policy)

            # HSTS from settings (only when not DEBUG)
            hsts_seconds = getattr(settings, 'SECURE_HSTS_SECONDS', 0)
            if (not settings.DEBUG) and hsts_seconds:
                hsts_parts = [f"max-age={int(hsts_seconds)}"]
                if getattr(settings, 'SECURE_HSTS_INCLUDE_SUBDOMAINS', False):
                    hsts_parts.append('includeSubDomains')
                if getattr(settings, 'SECURE_HSTS_PRELOAD', False):
                    hsts_parts.append('preload')
                response.setdefault('Strict-Transport-Security', '; '.join(hsts_parts))

            # Cross-origin isolation: conditional on DEBUG and COEP_EXEMPT_PATHS
            coep_exempt = getattr(settings, 'COEP_EXEMPT_PATHS', []) or []
            if (not settings.DEBUG) and not any(request.path.startswith(p) for p in coep_exempt):
                response.setdefault('Cross-Origin-Embedder-Policy', 'require-corp')
                response.setdefault('Cross-Origin-Resource-Policy', 'same-site')

        except Exception:
            # Best-effort: do not raise during error handling
            pass

        return response


class SecurityHeadersMiddleware:
    """Set strict security headers including a Content-Security-Policy.

    CSP is built from two allow-lists in settings: `CSP_TRUSTED_CDNS` and
    `CSP_PAYMENT_GATEWAYS`. Inline scripts are blocked by omitting
    'unsafe-inline' from `script-src`.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        # Build CSP from settings (include common CDNs by default)
        cdns = _effective_cdns()
        payments = getattr(settings, 'CSP_PAYMENT_GATEWAYS', []) or []
        # Compose sources; do not include 'unsafe-inline' so inline scripts/styles are blocked
        def join_src(lst):
            return ' '.join(lst) if lst else ''

        script_src = ["'self'", "'unsafe-inline'"] + cdns + payments
        style_src = ["'self'", "'unsafe-inline'"] + cdns
        img_src = ["'self'", 'data:']
        connect_src = ["'self'"] + payments
        frame_src = ["'self'"] + cdns + payments
        # Ensure known external download host is allowed for frames
        if 'https://download.mql5.com' not in frame_src:
            frame_src.append('https://download.mql5.com')
        # Allow about: (blank) and data: URIs which can be used for empty or dynamic iframes
        if 'about:' not in frame_src:
            frame_src.append('about:')
        if 'data:' not in frame_src:
            frame_src.append('data:')
        font_src = cdns

        # Do not add 'unsafe-inline' here; inline scripts/styles must be
        # handled by externalizing assets or using nonces/hashes. Keep the
        # policy strict by default.

        # In DEBUG allow inline scripts/styles to support local dev front-end files
        if settings.DEBUG:
            # Allow inline scripts/styles and evaluation locally (useful for dev builds)
            # NOTE: This relaxes the policy and MUST NOT be enabled in production.
            script_src = ["'self'", "'unsafe-inline'", "'unsafe-eval'"] + cdns + payments
            style_src = ["'self'", "'unsafe-inline'"] + cdns

        # Base CSP: default to 'self' and allow only configured external hosts
        csp_parts = [
            "default-src 'self'",
            f"script-src {join_src(script_src)}",
            f"style-src {join_src(style_src)}",
            f"img-src {join_src(img_src)}",
            f"frame-src {join_src(frame_src)}",
            f"connect-src {join_src(connect_src)}",
        ]

        if font_src:
            csp_parts.append(f"font-src {join_src(font_src)}")

        # Disallow plugins and base-uri for extra safety
        csp_parts.append("object-src 'none'")
        csp_parts.append("base-uri 'none'")

        csp_value = '; '.join(csp_parts) + ';'

        # Required headers per policy
        response['Content-Security-Policy'] = csp_value
        response['X-Content-Type-Options'] = 'nosniff'
        response['Referrer-Policy'] = 'same-origin'
        response['X-Frame-Options'] = 'SAMEORIGIN'
        # Restrict powerful browser features to reduce client-side risk
        permissions_policy = "geolocation=(), camera=(), microphone=(), payment=()"
        response['Permissions-Policy'] = permissions_policy
        # Include legacy Feature-Policy header for older user agents
        response['Feature-Policy'] = permissions_policy
        # Cross-origin isolation headers: apply only in production and when not exempt
        coep_exempt = getattr(settings, 'COEP_EXEMPT_PATHS', []) or []
        if (not settings.DEBUG) and not any(request.path.startswith(p) for p in coep_exempt):
            response['Cross-Origin-Embedder-Policy'] = 'same-origin'
            response['Cross-Origin-Resource-Policy'] = 'same-site'

        # HSTS - build from settings and only apply in non-debug (production) environments
        hsts_seconds = getattr(settings, 'SECURE_HSTS_SECONDS', 0)
        if not settings.DEBUG and hsts_seconds:
            hsts_parts = [f"max-age={int(hsts_seconds)}"]
            if getattr(settings, 'SECURE_HSTS_INCLUDE_SUBDOMAINS', False):
                hsts_parts.append('includeSubDomains')
            if getattr(settings, 'SECURE_HSTS_PRELOAD', False):
                hsts_parts.append('preload')
            response.headers['Strict-Transport-Security'] = '; '.join(hsts_parts)

        return response


from django.utils.deprecation import MiddlewareMixin


class StaticFilesSecurityMiddleware(MiddlewareMixin):
    """Ensure security headers are applied to static file responses.

    WhiteNoise may serve static files in a way that bypasses some response
    processing. This middleware unconditionally applies the same security
    headers for requests under `/static/` so assets receive CSP, HSTS,
    X-Frame-Options, X-Content-Type-Options and Referrer-Policy.
    """

    def process_response(self, request, response):
        # Only apply to static file responses
        path = (request.path or '')
        if path.startswith('/static/'):
            logger.debug('StaticFilesSecurityMiddleware processing response for %s', path)
            # Visible confirmation in stdout so dev server shows it immediately
            try:
                print(f"StaticFilesSecurityMiddleware applied for {path}")
            except Exception:
                pass
            # Mirror the production policy here but allow debug relaxations
            cdns = _effective_cdns()
            payments = getattr(settings, 'CSP_PAYMENT_GATEWAYS', []) or []

            def join_src(lst):
                return ' '.join(lst) if lst else ''

            script_src = ["'self'", "'unsafe-inline'"] + cdns + payments
            style_src = ["'self'", "'unsafe-inline'"] + cdns
            img_src = ["'self'", 'data:']
            connect_src = ["'self'"] + payments
            frame_src = ["'self'"] + cdns + payments
            if 'https://download.mql5.com' not in frame_src:
                frame_src.append('https://download.mql5.com')
            # Always allow about: (blank) and data: URIs for dynamic/blank iframes
            if 'about:' not in frame_src:
                frame_src.append('about:')
            if 'data:' not in frame_src:
                frame_src.append('data:')

            if settings.DEBUG:
                script_src = ["'self'", "'unsafe-inline'", "'unsafe-eval'"] + cdns + payments
                style_src = ["'self'", "'unsafe-inline'"] + cdns

            csp_parts = [
                "default-src 'self'",
                f"script-src {join_src(script_src)}",
                f"style-src {join_src(style_src)}",
                f"img-src {join_src(img_src)}",
                f"connect-src {join_src(connect_src)}",
                f"frame-src {join_src(frame_src)}",
                "object-src 'none'",
                "base-uri 'none'",
            ]

            csp_value = '; '.join(csp_parts) + ';'

            response['Content-Security-Policy'] = csp_value
            response['X-Content-Type-Options'] = 'nosniff'
            response['Referrer-Policy'] = 'same-origin'
            response['X-Frame-Options'] = 'SAMEORIGIN'
            # a small debug header to confirm middleware ran
            response['X-Static-Security-Middleware'] = 'applied'

            # Restrict powerful browser features for static responses as well
            permissions_policy = "geolocation=(), camera=(), microphone=(), payment=()"
            response['Permissions-Policy'] = permissions_policy
            response['Feature-Policy'] = permissions_policy
            # Cross-origin isolation headers for static responses: only in production and when not exempt
            coep_exempt = getattr(settings, 'COEP_EXEMPT_PATHS', []) or []
            if (not settings.DEBUG) and not any(request.path.startswith(p) for p in coep_exempt):
                response['Cross-Origin-Embedder-Policy'] = 'same-origin'
                response['Cross-Origin-Resource-Policy'] = 'same-site'

            # HSTS - build from settings and apply for static files in non-debug environments
            hsts_seconds = getattr(settings, 'SECURE_HSTS_SECONDS', 0)
            if not settings.DEBUG and hsts_seconds:
                hsts_parts = [f"max-age={int(hsts_seconds)}"]
                if getattr(settings, 'SECURE_HSTS_INCLUDE_SUBDOMAINS', False):
                    hsts_parts.append('includeSubDomains')
                if getattr(settings, 'SECURE_HSTS_PRELOAD', False):
                    hsts_parts.append('preload')
                response['Strict-Transport-Security'] = '; '.join(hsts_parts)

        return response

class APIMonitoringMiddleware:
    """Monitor API enumeration and excessive 401/403 responses per IP.

    Settings (optional):
      - API_MONITOR_ENUM_WINDOW (seconds, default 300)
      - API_MONITOR_ENUM_UNIQUE_THRESHOLD (unique paths, default 50)
      - API_MONITOR_AUTH_WINDOW (seconds, default 600)
      - API_MONITOR_AUTH_THRESHOLD (count, default 20)
      - API_MONITOR_ALERT_MIN_INTERVAL (seconds between alerts per IP, default 3600)

    This middleware stores lightweight per-IP state in Django's cache and
    emits structured warnings when thresholds are exceeded. It's intentionally
    conservative (logging only) so it can be enabled safely without blocking
    legitimate traffic.
    """

    def __init__(self, get_response):
        self.get_response = get_response
        self.enum_window = getattr(settings, 'API_MONITOR_ENUM_WINDOW', 300)
        self.enum_threshold = getattr(settings, 'API_MONITOR_ENUM_UNIQUE_THRESHOLD', 50)
        self.auth_window = getattr(settings, 'API_MONITOR_AUTH_WINDOW', 600)
        self.auth_threshold = getattr(settings, 'API_MONITOR_AUTH_THRESHOLD', 20)
        self.alert_min_interval = getattr(settings, 'API_MONITOR_ALERT_MIN_INTERVAL', 3600)
        # Recipients may be configured in settings; default to requested addresses
        self.recipients = getattr(
            settings,
            'API_MONITOR_ALERT_RECIPIENTS',
            ['support@vtindex.com', 'tamizharasan@vtindex.com', 'iyyanar@vtindex.com'],
        )
        self.from_email = getattr(settings, 'DEFAULT_FROM_EMAIL', getattr(settings, 'SERVER_EMAIL', 'no-reply@vtindex.com'))

    def __call__(self, request):
        start_ts = time.time()
        response = self.get_response(request)

        try:
            path = (request.path or '')
            # Only monitor API-like traffic to reduce noise
            if not path.startswith('/api/'):
                return response

            ip = request.META.get('REMOTE_ADDR', 'unknown')
            now = time.time()
            key = f"api_monitor:{ip}"

            state = cache.get(key) or {}

            # Normalize stored types (previous versions may have stored lists)
            paths = set(state.get('paths') or [])
            paths_first = state.get('paths_first', now)
            auth_times = state.get('auth_times') or []
            last_alert = state.get('last_alert', 0)

            # Expire / reset path set when window elapses
            if now - paths_first > self.enum_window:
                paths = set()
                paths_first = now

            paths.add(path)

            # Track auth failures (401/403)
            status = getattr(response, 'status_code', None)
            if status in (401, 403):
                # prune old timestamps outside auth_window
                auth_times = [t for t in auth_times if now - t <= self.auth_window]
                auth_times.append(now)

            # Check enumeration threshold
            if len(paths) >= self.enum_threshold and (now - last_alert) > self.alert_min_interval:
                logger.warning(
                    'API_ENUM_DETECTED ip=%s unique_paths=%d first_seen=%s sample_path=%s',
                    ip, len(paths), time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(paths_first)), path,
                )
                # Persist and notify (DB + webhook + email)
                try:
                    alerting.record_alert('ENUM', ip=ip, path=path, details={'unique_paths': len(paths), 'first_seen': paths_first})
                except Exception:
                    logger.exception('Failed to persist enumeration alert')
                try:
                    # webhook/Slack notify (best-effort)
                    alerting.notify_webhook('ENUM', ip=ip, path=path, details={'unique_paths': len(paths), 'first_seen': paths_first})
                except Exception:
                    logger.exception('Failed to notify webhook for enumeration')
                # send email alert (best-effort)
                try:
                    # Build authenticated user representation if available
                    user = getattr(request, 'user', None)
                    if user and getattr(user, 'is_authenticated', False):
                        user_email = getattr(user, 'email', None) or getattr(user, 'username', None)
                        user_repr = f"{getattr(user, 'username', str(user))} <{user_email}>" if user_email else getattr(user, 'username', str(user))
                    else:
                        user_email = None
                        user_repr = 'anonymous'

                    subject = f"[Security] API enumeration detected from {ip}"
                    body = (
                        f"An API enumeration pattern was detected.\n\n"
                        f"IP: {ip}\n"
                        f"Authenticated user: {user_repr}\n"
                        f"Unique /api/ paths seen: {len(paths)}\n"
                        f"First seen (UTC): {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(paths_first))}\n"
                        f"Sample path: {path}\n"
                    )
                    # Treat the first configured recipient as primary To and the rest as CC
                    to_list = [self.recipients[0]] if self.recipients else []
                    cc_list = self.recipients[1:] if len(self.recipients) > 1 else []
                    email = EmailMessage(subject, body, self.from_email, to=to_list, cc=cc_list)
                    email.send(fail_silently=True)
                except Exception:
                    logger.exception('Failed to send API enumeration alert email')
                last_alert = now

            # Check excessive auth failures
            if len(auth_times) >= self.auth_threshold and (now - last_alert) > self.alert_min_interval:
                logger.warning(
                    'API_AUTH_ABUSE ip=%s failures=%d window_seconds=%d last_path=%s',
                    ip, len(auth_times), self.auth_window, path,
                )
                try:
                    alerting.record_alert('AUTH_ABUSE', ip=ip, path=path, details={'failures': len(auth_times), 'window': self.auth_window})
                except Exception:
                    logger.exception('Failed to persist auth abuse alert')
                try:
                    alerting.notify_webhook('AUTH_ABUSE', ip=ip, path=path, details={'failures': len(auth_times), 'window': self.auth_window})
                except Exception:
                    logger.exception('Failed to notify webhook for auth abuse')
                try:
                    # Build authenticated user representation if available
                    user = getattr(request, 'user', None)
                    if user and getattr(user, 'is_authenticated', False):
                        user_email = getattr(user, 'email', None) or getattr(user, 'username', None)
                        user_repr = f"{getattr(user, 'username', str(user))} <{user_email}>" if user_email else getattr(user, 'username', str(user))
                    else:
                        user_email = None
                        user_repr = 'anonymous'

                    subject = f"[Security] Excessive API auth failures from {ip}"
                    body = (
                        f"Excessive authentication failures detected for API endpoints.\n\n"
                        f"IP: {ip}\n"
                        f"Authenticated user: {user_repr}\n"
                        f"Failure count (last {self.auth_window} seconds): {len(auth_times)}\n"
                        f"Last path: {path}\n"
                    )
                    to_list = [self.recipients[0]] if self.recipients else []
                    cc_list = self.recipients[1:] if len(self.recipients) > 1 else []
                    email = EmailMessage(subject, body, self.from_email, to=to_list, cc=cc_list)
                    email.send(fail_silently=True)
                except Exception:
                    logger.exception('Failed to send API auth abuse alert email')
                last_alert = now

            # Persist trimmed state in cache
            # convert paths back to list for pickling/storage
            store = {
                'paths': list(paths),
                'paths_first': paths_first,
                'auth_times': auth_times,
                'last_alert': last_alert,
            }
            # keep the cache TTL at least long enough to cover windows
            ttl = max(self.enum_window, self.auth_window) * 2
            cache.set(key, store, ttl)

        except Exception:
            logger.exception('Error in APIMonitoringMiddleware')

        # --- Cloudflare / cookie support helpers ---
        try:
            # If Cloudflare set a cf_clearance cookie in the response, log it
            # and copy to a namespaced cookie so application-level JS can read it.
            cf_cookie = None
            try:
                cf = response.cookies.get('cf_clearance')
                if cf:
                    cf_cookie = cf.value
            except Exception:
                cf_cookie = None

            if cf_cookie:
                logger.info('Detected cf_clearance cookie in response for %s; copying to cf_clearance_copy', request.path)
                try:
                    # Set a readable copy on base path for client-side scripts. This is not
                    # identical to Cloudflare's own cookie but helps debugging/visibility.
                    secure_flag = not getattr(settings, 'DEBUG', False)
                    cookie_domain = getattr(settings, 'COOKIE_DOMAIN', None)
                    response.set_cookie('cf_clearance_copy', cf_cookie, httponly=True,
                                        secure=secure_flag, samesite='Strict', path='/', domain=cookie_domain)
                except Exception:
                    logger.exception('Failed to set cf_clearance_copy cookie')

            # If no cf_clearance present but this is the base URL (or configured
            # base-cookie trigger), create a copy cookie so frontends have a
            # consistent name to check. Controlled by settings to avoid surprising
            # behavior in production.
            try:
                enable_base_cookie = getattr(settings, 'ENABLE_BASE_CF_COPY', False)
                base_paths = getattr(settings, 'BASE_CF_COPY_PATHS', ['/'])
            except Exception:
                enable_base_cookie = False
                base_paths = ['/']

            try:
                if enable_base_cookie and not cf_cookie:
                    for bp in base_paths:
                        if request.path == bp or request.path.startswith(bp):
                            secure_flag = not getattr(settings, 'DEBUG', False)
                            cookie_domain = getattr(settings, 'COOKIE_DOMAIN', None)
                            # value empty by default; frontend can set it or use as marker
                            response.set_cookie('cf_clearance_copy', '', httponly=False,
                                                secure=secure_flag, samesite='Lax', path='/', domain=cookie_domain)
                            logger.debug('Set empty cf_clearance_copy on base path %s', bp)
                            break
            except Exception:
                logger.exception('Failed to set base cf_clearance_copy cookie')

            # As a convenience: when a login request succeeds, set an application-level
            # marker cookie at the base path so frontends can detect a completed login
            # prior to Cloudflare issuing its challenge cookie. This does NOT replace
            # Cloudflare's own cf_clearance token.
            try:
                if request.path == '/api/login/' and response.status_code in (200, 202):
                    secure_flag = not getattr(settings, 'DEBUG', False)
                    cookie_domain = getattr(settings, 'COOKIE_DOMAIN', None)
                    # small opaque marker; frontends may read this and act accordingly
                    response.set_cookie('app_login_marker', '1', httponly=False,
                                        secure=secure_flag, samesite='Lax', path='/', domain=cookie_domain)
            except Exception:
                logger.exception('Failed to set app_login_marker cookie')
        except Exception:
            # Do not allow cookie-handling to break request processing
            logger.exception('Error while handling cf_clearance/app marker cookies')

        return response
