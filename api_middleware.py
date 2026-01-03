from django.http import JsonResponse
from django.utils.deprecation import MiddlewareMixin
import json

class APIJSONResponseMiddleware(MiddlewareMixin):
    """
    Middleware to ensure API endpoints always return JSON responses,
    even for errors like 404, 500, etc.
    """
    def process_exception(self, request, exception):
        # Only handle API endpoints (both /api/, /client/, /admin-api/, and /ib-user/ paths)
        if (request.path.startswith('/api/') or request.path.startswith('/client/') or 
            request.path.startswith('/admin-api/') or request.path.startswith('/ib-user/')):
            # Log the error for debugging
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"API Exception in {request.path}: {str(exception)}")
            
            return JsonResponse({
                'error': 'Internal server error',
                'message': str(exception),
                'path': request.path            }, status=500)
        return None

    def process_response(self, request, response):
        # Only handle API endpoints (both /api/, /client/, /admin-api/, and /ib-user/ paths)
        if not (request.path.startswith('/api/') or request.path.startswith('/client/') or 
                request.path.startswith('/admin-api/') or request.path.startswith('/ib-user/')):
            return response
            
        # If it's already a JsonResponse, leave it alone
        if hasattr(response, 'json') or response.get('Content-Type', '').startswith('application/json'):
            return response
            
        # If it's an error response (4xx, 5xx) and not JSON, convert to JSON
        if 400 <= response.status_code < 600:
            try:
                # Try to extract meaningful error message
                content = response.content.decode('utf-8')
                
                # Handle common Django error pages
                if 'DoesNotExist' in content:
                    error_msg = 'Required data not found. Please ensure MT5 server settings are configured.'
                elif 'CSRF' in content or 'csrfmiddlewaretoken' in content:
                    error_msg = 'CSRF token missing or incorrect'
                elif 'Not Found' in content or response.status_code == 404:
                    error_msg = f'API endpoint not found: {request.path}'
                elif 'Forbidden' in content or response.status_code == 403:
                    error_msg = 'Access forbidden - please check authentication'
                elif 'Unauthorized' in content or response.status_code == 401:
                    error_msg = 'Authentication required - please login'
                elif '<!DOCTYPE' in content[:50]:  # HTML response
                    error_msg = f'Server returned HTML instead of JSON (HTTP {response.status_code})'
                else:
                    error_msg = f'Server error (HTTP {response.status_code})'
                    
                return JsonResponse({
                    'error': error_msg,
                    'status_code': response.status_code,
                    'path': request.path,
                    'method': request.method
                }, status=response.status_code)
            except Exception as e:
                return JsonResponse({
                    'error': 'Server error - unable to process response',
                    'status_code': response.status_code,
                    'path': request.path,
                    'details': str(e)
                }, status=response.status_code)
                
        return response