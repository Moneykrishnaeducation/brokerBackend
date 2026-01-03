"""
Custom error handler views for Django
"""
from django.shortcuts import render


def custom_404(request, exception=None):
    """
    Custom 404 error page handler
    """
    return render(request, '404.html', status=404)


def custom_500(request):
    """
    Custom 500 error page handler
    """
    return render(request, '500.html', status=500)


def custom_403(request, exception=None):
    """
    Custom 403 error page handler
    """
    return render(request, '403.html', status=403)
