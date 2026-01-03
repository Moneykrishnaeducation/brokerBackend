import logging
import time

from django.utils.deprecation import MiddlewareMixin


logger = logging.getLogger('access')


class RequestLoggingMiddleware(MiddlewareMixin):
    """Log each request after response with IP and user email.

    Format: 2025-12-23 13:00:00 INFO access "GET /path HTTP/1.1" 200 1234 ip=<IP> user=<EMAIL>
    """

    def process_request(self, request):
        request._start_time = time.time()

    def process_response(self, request, response):
        try:
            start = getattr(request, '_start_time', time.time())
            duration = time.time() - start
            method = request.method
            path = request.get_full_path()
            protocol = request.META.get('SERVER_PROTOCOL', 'HTTP/1.1')
            status = getattr(response, 'status_code', 0)
            length = len(getattr(response, 'content', b'')) if hasattr(response, 'content') else 0

            # Determine client IP (respect X-Forwarded-For if present)
            xff = request.META.get('HTTP_X_FORWARDED_FOR')
            if xff:
                ip = xff.split(',')[0].strip()
            else:
                ip = request.META.get('REMOTE_ADDR', '-')

            # Get user email if authenticated; fall back to request body for login attempts
            user = getattr(request, 'user', None)
            email = '-'
            try:
                if user and getattr(user, 'is_authenticated', False):
                    email = getattr(user, 'email', '-') or '-'
                else:
                    # Try to extract from POST form
                    try:
                        if hasattr(request, 'POST') and request.POST:
                            email = request.POST.get('email') or request.POST.get('username') or email
                    except Exception:
                        pass
                    # If still missing, try JSON body
                    if (email == '-' or not email) and request.method in ('POST', 'PUT'):
                        try:
                            content_type = request.META.get('CONTENT_TYPE', '')
                            if 'application/json' in content_type:
                                import json
                                body = request.body.decode('utf-8') if isinstance(request.body, (bytes, bytearray)) else str(request.body)
                                if body:
                                    data = json.loads(body)
                                    email = data.get('email') or data.get('username') or email
                        except Exception:
                            pass
                    email = email or '-'
            except Exception:
                email = '-'

            # Log structured fields so formatter can produce JSON
            logger.info(f'"{method} {path} {protocol}" {status} {length}', extra={
                'ip': ip,
                'user_email': email,
                'method': method,
                'path': path,
                'protocol': protocol,
                'status': status,
                'length': length,
                'duration': round(duration, 3),
            })
        except Exception:
            # Avoid breaking response flow on logging errors
            logger.exception('Failed to log request')

        return response
