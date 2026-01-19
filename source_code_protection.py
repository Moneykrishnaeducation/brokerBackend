"""
SECURITY: Middleware to block access to Python source files via HTTP.

Blocks:
- .py, .pyc, .pyo files (Python source code)
- .env files (environment variables)
- .git directories (version control)

This is the primary defense against exposing your backend code.
"""

from django.http import HttpResponseForbidden
from django.conf import settings
import logging

logger = logging.getLogger(__name__)


class SourceCodeProtectionMiddleware:
    """
    Blocks HTTP requests to Python source files and sensitive files.
    """
    
    BLOCKED_EXTENSIONS = (
        '.py',           # Python source
        '.pyc',          # Compiled Python
        '.pyo',          # Optimized Python
        '.env',          # Environment variables
        '.git',          # Git metadata
        '.gitignore',    # Git ignore
    )
    
    BLOCKED_PATHS = (
        '/adminPanel/',
        '/brokerBackend/',
        '/clientPanel/',
        '/__pycache__/',
        '/.git/',
    )
    
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        path = request.path.lower()
        
        # Block Python files
        for ext in self.BLOCKED_EXTENSIONS:
            if path.endswith(ext):
                logger.warning(f"BLOCKED: Attempted access to {request.path} from {request.META.get('REMOTE_ADDR')}")
                return HttpResponseForbidden("Access Denied")
        
        # Block directories
        for blocked_path in self.BLOCKED_PATHS:
            if blocked_path in path:
                logger.warning(f"BLOCKED: Attempted access to {request.path} from {request.META.get('REMOTE_ADDR')}")
                return HttpResponseForbidden("Access Denied")
        
        response = self.get_response(request)
        return response
