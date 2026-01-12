"""
Cookie Management Utility for Auto-Clearing Cookies
Handles centralized cookie storage and auto-clearing based on backend-configured time
"""

import json
import time
from datetime import datetime, timedelta
from django.conf import settings
from django.core.cache import cache
import logging

logger = logging.getLogger(__name__)


class CookieManager:
    """
    Centralized cookie management with auto-clear functionality.
    
    Configuration in settings.py:
    COOKIE_AUTO_CLEAR_CONFIG = {
        'enabled': True,                    # Enable/disable auto-clear
        'access_token_lifetime': 300,      # seconds (1 hour default)
        'refresh_token_lifetime': 2592000,  # seconds (30 days default)
        'session_timeout': 1800,            # seconds (30 mins idle timeout)
        'remember_me_lifetime': 604800,     # seconds (7 days for remember-me tokens)
    }
    """
    
    # Default cookie configuration (in seconds)
    DEFAULT_CONFIG = {
        'enabled': True,
        'access_token_lifetime': 300,              # 1 hour
        'refresh_token_lifetime': 2592000,          # 30 days
        'session_timeout': 1800,                    # 30 mins
        'remember_me_access_lifetime': 604800,      # 7 days
        'remember_me_refresh_lifetime': 2592000,    # 30 days
    }
    
    # Cookie names that require auto-clear tracking
    AUTH_COOKIES = [
        'jwt_token', 'access_token', 'accessToken',
        'refresh_token', 'refreshToken',
        'userName', 'userEmail', 'userRole', 'user_role', 'UserRole',
    ]
    
    @staticmethod
    def get_config():
        """Get cookie auto-clear configuration from settings"""
        config = getattr(settings, 'COOKIE_AUTO_CLEAR_CONFIG', {})
        # Merge with defaults
        merged_config = CookieManager.DEFAULT_CONFIG.copy()
        merged_config.update(config)
        return merged_config
    
    @staticmethod
    def get_token_lifetime(token_type='access', remember_me=False):
        """
        Get token lifetime in seconds based on token type and remember-me flag
        
        Args:
            token_type: 'access' or 'refresh'
            remember_me: whether remember-me is enabled
            
        Returns:
            int: lifetime in seconds
        """
        config = CookieManager.get_config()
        
        if remember_me:
            if token_type == 'refresh':
                return config.get('remember_me_refresh_lifetime', 2592000)
            else:  # access
                return config.get('remember_me_access_lifetime', 604800)
        else:
            if token_type == 'refresh':
                return config.get('refresh_token_lifetime', 2592000)
            else:  # access
                return config.get('access_token_lifetime', 300)
    
    @staticmethod
    def store_cookie_metadata(user_id, token_identifier, token_type='access', 
                              remember_me=False, ip_address=None):
        """
        Store cookie metadata in cache for tracking expiration
        
        Args:
            user_id: user ID
            token_identifier: unique token identifier/hash
            token_type: 'access' or 'refresh'
            remember_me: whether remember-me is enabled
            ip_address: user IP address for security
        """
        if not CookieManager.get_config()['enabled']:
            return
        
        try:
            lifetime = CookieManager.get_token_lifetime(token_type, remember_me)
            
            # Create cache key for tracking
            cache_key = f"cookie_meta:{user_id}:{token_type}:{token_identifier}"
            
            metadata = {
                'user_id': user_id,
                'token_type': token_type,
                'token_identifier': token_identifier,
                'created_at': datetime.utcnow().isoformat(),
                'expires_at': (datetime.utcnow() + timedelta(seconds=lifetime)).isoformat(),
                'lifetime_seconds': lifetime,
                'remember_me': remember_me,
                'ip_address': ip_address,
            }
            
            # Store in cache with expiration
            cache.set(cache_key, metadata, timeout=lifetime)
            
            logger.debug(f"Cookie metadata stored: user={user_id}, type={token_type}, lifetime={lifetime}s")
            
        except Exception as e:
            logger.exception(f"Failed to store cookie metadata: {e}")
    
    @staticmethod
    def get_cookie_expiry_time(user_id, token_type='access', remember_me=False):
        """
        Get the expiry datetime for a token-based cookie
        
        Args:
            user_id: user ID
            token_type: 'access' or 'refresh'
            remember_me: whether remember-me is enabled
            
        Returns:
            datetime: expiration time in UTC
        """
        lifetime = CookieManager.get_token_lifetime(token_type, remember_me)
        return datetime.utcnow() + timedelta(seconds=lifetime)
    
    @staticmethod
    def set_auth_cookies(response, tokens_dict, user_data=None, 
                        remember_me=False, secure_flag=True, 
                        cookie_domain=None, user_id=None, ip_address=None):
        """
        Set authentication cookies with auto-clear tracking
        
        Args:
            response: Django response object
            tokens_dict: dict with 'access' and 'refresh' tokens
            user_data: dict with user info (email, name, role, etc.)
            remember_me: whether remember-me is enabled
            secure_flag: whether to use secure flag
            cookie_domain: cookie domain
            user_id: user ID for tracking
            ip_address: user IP for security
            
        Returns:
            response: updated response object
        """
        try:
            config = CookieManager.get_config()
            
            if not config['enabled']:
                # Just set cookies without metadata tracking
                return CookieManager._set_cookies_without_tracking(
                    response, tokens_dict, user_data, remember_me,
                    secure_flag, cookie_domain
                )
            
            # Set tokens with proper lifetime
            access_token = tokens_dict.get('access')
            refresh_token = tokens_dict.get('refresh')
            
            access_lifetime = CookieManager.get_token_lifetime('access', remember_me)
            refresh_lifetime = CookieManager.get_token_lifetime('refresh', remember_me)
            
            # Set access token
            if access_token:
                response.set_cookie(
                    'jwt_token', access_token,
                    httponly=True, secure=secure_flag, samesite='Strict',
                    path='/', max_age=access_lifetime, domain=cookie_domain
                )
                response.set_cookie(
                    'access_token', access_token,
                    httponly=True, secure=secure_flag, samesite='Strict',
                    path='/', max_age=access_lifetime, domain=cookie_domain
                )
                response.set_cookie(
                    'accessToken', access_token,
                    httponly=True, secure=secure_flag, samesite='Strict',
                    path='/', max_age=access_lifetime, domain=cookie_domain
                )
                
                # Store metadata for tracking
                if user_id:
                    token_hash = hash(access_token) % ((2 ** 31) - 1)
                    CookieManager.store_cookie_metadata(
                        user_id, str(token_hash), 'access',
                        remember_me, ip_address
                    )
            
            # Set refresh token
            if refresh_token:
                response.set_cookie(
                    'refresh_token', refresh_token,
                    httponly=True, secure=secure_flag, samesite='Strict',
                    path='/', max_age=refresh_lifetime, domain=cookie_domain
                )
                response.set_cookie(
                    'refreshToken', refresh_token,
                    httponly=True, secure=secure_flag, samesite='Strict',
                    path='/', max_age=refresh_lifetime, domain=cookie_domain
                )
                
                # Store metadata for tracking
                if user_id:
                    token_hash = hash(refresh_token) % ((2 ** 31) - 1)
                    CookieManager.store_cookie_metadata(
                        user_id, str(token_hash), 'refresh',
                        remember_me, ip_address
                    )
            
            # Set user metadata cookies (non-HttpOnly for frontend access)
            if user_data:
                user_name = user_data.get('username') or user_data.get('email', '')
                user_email = user_data.get('email', '')
                user_role = user_data.get('role', 'user')
                
                if user_name:
                    response.set_cookie(
                        'userName', user_name,
                        httponly=True, secure=secure_flag, samesite='Strict',
                        path='/', max_age=access_lifetime, domain=cookie_domain
                    )
                
                if user_email:
                    response.set_cookie(
                        'userEmail', user_email,
                        httponly=True, secure=secure_flag, samesite='Strict',
                        path='/', max_age=access_lifetime, domain=cookie_domain
                    )
                
                if user_role:
                    response.set_cookie(
                        'userRole', user_role,
                        httponly=True, secure=secure_flag, samesite='Strict',
                        path='/', max_age=access_lifetime, domain=cookie_domain
                    )
            
            logger.info(f"Auth cookies set with auto-clear enabled. Access TTL: {access_lifetime}s, Refresh TTL: {refresh_lifetime}s")
            
        except Exception as e:
            logger.exception(f"Error setting auth cookies: {e}")
        
        return response
    
    @staticmethod
    def _set_cookies_without_tracking(response, tokens_dict, user_data=None, 
                                     remember_me=False, secure_flag=True, 
                                     cookie_domain=None):
        """Internal method: set cookies without metadata tracking"""
        access_token = tokens_dict.get('access')
        refresh_token = tokens_dict.get('refresh')
        
        access_lifetime = CookieManager.get_token_lifetime('access', remember_me)
        refresh_lifetime = CookieManager.get_token_lifetime('refresh', remember_me)
        
        if access_token:
            for cookie_name in ['jwt_token', 'access_token', 'accessToken']:
                response.set_cookie(
                    cookie_name, access_token,
                    httponly=True, secure=secure_flag, samesite='Strict',
                    path='/', max_age=access_lifetime, domain=cookie_domain
                )
        
        if refresh_token:
            for cookie_name in ['refresh_token', 'refreshToken']:
                response.set_cookie(
                    cookie_name, refresh_token,
                    httponly=True, secure=secure_flag, samesite='Strict',
                    path='/', max_age=refresh_lifetime, domain=cookie_domain
                )
        
        if user_data:
            user_name = user_data.get('username') or user_data.get('email', '')
            user_email = user_data.get('email', '')
            user_role = user_data.get('role', 'user')
            
            if user_name:
                response.set_cookie(
                    'userName', user_name,
                    httponly=True, secure=secure_flag, samesite='Strict',
                    path='/', max_age=access_lifetime, domain=cookie_domain
                )
            
            if user_email:
                response.set_cookie(
                    'userEmail', user_email,
                    httponly=True, secure=secure_flag, samesite='Strict',
                    path='/', max_age=access_lifetime, domain=cookie_domain
                )
            
            if user_role:
                response.set_cookie(
                    'userRole', user_role,
                    httponly=True, secure=secure_flag, samesite='Strict',
                    path='/', max_age=access_lifetime, domain=cookie_domain
                )
        
        return response
    
    @staticmethod
    def clear_auth_cookies(response, secure_flag=True, cookie_domain=None):
        """
        Clear all authentication cookies
        
        Args:
            response: Django response object
            secure_flag: whether to use secure flag
            cookie_domain: cookie domain
            
        Returns:
            response: updated response object
        """
        try:
            all_cookies = [
                'jwt_token', 'access_token', 'accessToken',
                'refresh_token', 'refreshToken',
                'userName', 'userEmail', 'userRole', 'user_role', 'UserRole',
                'current_page', 'themeMode', 'login_verification_pending',
                'role', 'admin_app_loaded', 'sessionid', 'csrftoken',
                'user_name', 'username'
            ]
            
            for cookie_name in all_cookies:
                response.set_cookie(
                    cookie_name,
                    '',
                    httponly=True,
                    secure=secure_flag,
                    samesite='Strict',
                    path='/',
                    max_age=0,
                    domain=cookie_domain
                )
            
            logger.info("All auth cookies cleared")
            
        except Exception as e:
            logger.exception(f"Error clearing auth cookies: {e}")
        
        return response
    
    @staticmethod
    def is_cookie_expired(user_id, token_type='access', remember_me=False):
        """
        Check if a cookie should be expired based on backend configuration
        
        Args:
            user_id: user ID
            token_type: 'access' or 'refresh'
            remember_me: whether remember-me is enabled
            
        Returns:
            bool: True if expired, False if still valid
        """
        try:
            expiry_time = CookieManager.get_cookie_expiry_time(user_id, token_type, remember_me)
            return datetime.utcnow() >= expiry_time
        except Exception as e:
            logger.exception(f"Error checking cookie expiry: {e}")
            return False
    
    @staticmethod
    def get_session_remaining_time(user_id, token_type='access', remember_me=False):
        """
        Get remaining time in seconds for a token cookie
        
        Args:
            user_id: user ID
            token_type: 'access' or 'refresh'
            remember_me: whether remember-me is enabled
            
        Returns:
            int: remaining seconds, or 0 if expired
        """
        try:
            expiry_time = CookieManager.get_cookie_expiry_time(user_id, token_type, remember_me)
            remaining = (expiry_time - datetime.utcnow()).total_seconds()
            return max(0, int(remaining))
        except Exception as e:
            logger.exception(f"Error calculating remaining time: {e}")
            return 0
