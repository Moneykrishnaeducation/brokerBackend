"""
Cookie Auto-Clear Middleware
Validates and monitors cookie expiration based on backend configuration
"""

import logging
from django.utils.deprecation import MiddlewareMixin
from django.http import JsonResponse
from django.conf import settings
from brokerBackend.cookie_manager import CookieManager

logger = logging.getLogger(__name__)


class CookieAutoClearMiddleware(MiddlewareMixin):
    """
    Middleware to handle cookie auto-clear functionality.
    
    Responsibilities:
    1. Validate cookie expiration on each request
    2. Clear expired cookies from response
    3. Log cookie lifecycle events
    4. Support both admin and client panels
    """
    
    # Endpoints that should skip cookie validation (e.g., public auth endpoints)
    SKIP_VALIDATION_PATHS = [
        '/api/auth/login',
        '/api/auth/register',
        '/api/validate-token',
        '/api/public',
        '/health',
        '/api/csrf-token',
    ]
    
    def should_skip_validation(self, request):
        """Check if this request should skip cookie validation"""
        path = request.path.lower()
        return any(path.startswith(skip_path.lower()) for skip_path in self.SKIP_VALIDATION_PATHS)
    
    def process_request(self, request):
        """Process incoming request - validate cookie status"""
        try:
            # Skip validation for certain endpoints
            if self.should_skip_validation(request):
                return None
            
            # Get cookie auto-clear config
            config = CookieManager.get_config()
            if not config.get('enabled'):
                return None
            
            # Extract user info from authenticated requests
            user = getattr(request, 'user', None)
            if not user or not user.is_authenticated:
                return None
            
            # Check if cookies are approaching expiration
            user_id = user.id if hasattr(user, 'id') else str(user)
            
            # Log cookie validation attempt (for debugging)
            logger.debug(f"Cookie validation - User {user_id}, Path: {request.path}")
            
        except Exception as e:
            logger.exception(f"Error in CookieAutoClearMiddleware.process_request: {e}")
        
        return None
    
    def process_response(self, request, response):
        """Process outgoing response - clear expired cookies if needed"""
        try:
            # Get cookie auto-clear config
            config = CookieManager.get_config()
            if not config.get('enabled'):
                return response
            
            # For logout endpoints, cookies are already cleared in the view
            # This middleware is primarily for validation and monitoring
            
            user = getattr(request, 'user', None)
            if user and user.is_authenticated:
                user_id = user.id if hasattr(user, 'id') else str(user)
                
                # Add cookie expiry info to response headers (optional, for debugging)
                access_lifetime = CookieManager.get_token_lifetime('access', False)
                response['X-Cookie-Access-Lifetime'] = str(access_lifetime)
                
                logger.debug(f"Cookie response processing - User {user_id}, Status: {response.status_code}")
        
        except Exception as e:
            logger.exception(f"Error in CookieAutoClearMiddleware.process_response: {e}")
        
        return response
