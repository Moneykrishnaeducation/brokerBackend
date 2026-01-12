"""
Cookie Auto-Clear Diagnostic Endpoint
Helps verify that the cookie auto-clear system is working correctly
"""

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from brokerBackend.cookie_manager import CookieManager
from django.conf import settings
import logging

logger = logging.getLogger(__name__)


@csrf_exempt
def cookie_diagnostic_view(request):
    """
    Diagnostic endpoint to check cookie auto-clear configuration
    Access via: GET /api/cookie-diagnostic/
    """
    if request.method != 'GET':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    try:
        config = CookieManager.get_config()
        
        # Get current lifetimes
        access_lifetime = CookieManager.get_token_lifetime('access', False)
        refresh_lifetime = CookieManager.get_token_lifetime('refresh', False)
        remember_access = CookieManager.get_token_lifetime('access', True)
        remember_refresh = CookieManager.get_token_lifetime('refresh', True)
        
        # Check DEBUG mode
        is_debug = settings.DEBUG
        secure_flag = not is_debug
        
        diagnostics = {
            'status': 'OK',
            'debug_mode': is_debug,
            'secure_cookies': secure_flag,
            'config': {
                'enabled': config.get('enabled'),
                'access_token_lifetime': config.get('access_token_lifetime'),
                'refresh_token_lifetime': config.get('refresh_token_lifetime'),
                'session_timeout': config.get('session_timeout'),
                'remember_me_access_lifetime': config.get('remember_me_access_lifetime'),
                'remember_me_refresh_lifetime': config.get('remember_me_refresh_lifetime'),
            },
            'calculated_lifetimes': {
                'access_token': f"{access_lifetime}s ({access_lifetime//60}min)" if access_lifetime < 3600 else f"{access_lifetime}s ({access_lifetime//3600}h)",
                'refresh_token': f"{refresh_lifetime}s ({refresh_lifetime//86400}d)",
                'remember_me_access': f"{remember_access}s ({remember_access//3600}h)",
                'remember_me_refresh': f"{remember_refresh}s ({remember_refresh//86400}d)",
            },
            'recommendations': []
        }
        
        # Check for issues
        if not config.get('enabled'):
            diagnostics['recommendations'].append('⚠️ Auto-clear is DISABLED in config')
        
        if access_lifetime <= 0:
            diagnostics['recommendations'].append('⚠️ Access token lifetime is 0 or negative')
        
        if is_debug and not secure_flag:
            diagnostics['recommendations'].append('✅ Cookies are NOT secure in development (correct for localhost)')
        
        if not is_debug and secure_flag:
            diagnostics['recommendations'].append('✅ Cookies are secure in production')
        
        logger.info(f"📋 Cookie diagnostic check: access_lifetime={access_lifetime}s, enabled={config.get('enabled')}")
        
        return JsonResponse(diagnostics, safe=False)
    
    except Exception as e:
        logger.error(f"❌ Error in cookie_diagnostic_view: {str(e)}", exc_info=True)
        return JsonResponse({
            'status': 'ERROR',
            'error': str(e)
        }, status=500)
