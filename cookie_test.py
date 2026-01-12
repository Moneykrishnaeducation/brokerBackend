"""
Cookie Auto-Clear Testing Endpoint
Test endpoint to verify cookies are being set correctly with max_age
"""

from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from brokerBackend.cookie_manager import CookieManager
from django.conf import settings
import logging

logger = logging.getLogger(__name__)


@api_view(['POST'])
@permission_classes([AllowAny])
def test_cookie_view(request):
    """
    Test endpoint to set cookies and verify they're working
    POST /api/test-cookies/
    
    Response headers will include Set-Cookie with max_age values
    """
    try:
        # Get configuration
        config = CookieManager.get_config()
        
        # Create a test response
        response = Response({
            'status': 'OK',
            'message': 'Test cookies set',
            'config': config,
            'cookies_set': [
                'jwt_token',
                'access_token', 
                'refresh_token'
            ]
        })
        
        # Set test cookies using CookieManager
        test_tokens = {
            'access': 'test_access_token_12345',
            'refresh': 'test_refresh_token_67890'
        }
        
        test_user_data = {
            'username': 'test@example.com',
            'email': 'test@example.com',
            'role': 'test'
        }
        
        secure_flag = not settings.DEBUG
        
        logger.info(f"🧪 TEST: Setting test cookies")
        logger.info(f"   Debug mode: {settings.DEBUG}")
        logger.info(f"   Secure flag: {secure_flag}")
        logger.info(f"   Access lifetime: {config['access_token_lifetime']}s")
        
        # Use CookieManager to set cookies
        response = CookieManager.set_auth_cookies(
            response=response,
            tokens_dict=test_tokens,
            user_data=test_user_data,
            remember_me=False,
            secure_flag=secure_flag,
            cookie_domain=None,
            user_id=9999,  # Test user ID
            ip_address='127.0.0.1'
        )
        
        logger.info(f"🧪 TEST: Test cookies set successfully")
        logger.info(f"   Response cookies: {response.cookies.keys()}")
        
        # Add detailed response about the cookies
        response.data['response_cookies'] = {
            name: {
                'value': str(morsel.value)[:20] + '...' if len(str(morsel.value)) > 20 else str(morsel.value),
                'max_age': morsel.get('max-age'),
                'path': morsel.get('path'),
                'domain': morsel.get('domain'),
                'httponly': morsel.get('httponly'),
                'secure': morsel.get('secure'),
                'samesite': morsel.get('samesite')
            }
            for name, morsel in response.cookies.items()
        }
        
        return response
        
    except Exception as e:
        logger.exception(f"🧪 TEST: Error setting test cookies: {e}")
        return Response({
            'status': 'ERROR',
            'error': str(e),
            'message': 'Failed to set test cookies'
        }, status=500)
