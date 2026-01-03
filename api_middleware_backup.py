from django.http import JsonResponse
from django.utils.deprecation import MiddlewareMixin
import json

class APIJSONResponseMiddleware(MiddlewareMixin):    """
    Middleware to ensure API endpoints always return JSON responses,
    even for errors like 404, 500, etc.
    """
    def process_exception(self, request, exception):
        # Only handle API endpoints (both /api/, /client/, /admin-api/, and /ib-user/ paths)
        if (request.path.startswith('/api/') or request.path.startswith('/client/') or 
            request.path.startswith('/admin-api/') or request.path.startswith('/ib-user/')):
            return JsonResponse({
                'error': 'Internal server error',
                'message': str(exception)
            }, status=500)
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
                if 'DoesNotExist' in content:
                    error_msg = 'Required data not found. Please ensure MT5 server settings are configured.'
                elif 'CSRF' in content:
                    error_msg = 'CSRF token missing or incorrect'
                elif 'Not Found' in content:
                    error_msg = 'API endpoint not found'
                else:
                    error_msg = f'Server error (HTTP {response.status_code})'
                    
                return JsonResponse({
                    'error': error_msg,
                    'status_code': response.status_code
                }, status=response.status_code)
            except:
                return JsonResponse({
                    'error': 'Server error',
                    'status_code': response.status_code
                }, status=response.status_code)
                
        return response
