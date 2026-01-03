from django.contrib import admin
from django.urls import path, include, re_path
from django.views.decorators.csrf import csrf_exempt
# Import client resend view to create a quick alias for mismatched prefixes
from clientPanel.views import auth_views as client_auth_views
from django.conf.urls.i18n import i18n_patterns
from django.conf import settings
from django.conf.urls.static import static
from django.contrib.auth import views as auth_views
from django.views.static import serve
from django.views.generic import TemplateView


# Top-level urlpatterns (unprefixed). Keep admin and chat here so admin remains accessible
urlpatterns = [
    # Django admin interface (without custom login override)
    path('admin/', admin.site.urls),

    # Compatibility aliases: some frontends call the client API with a /client/api/ prefix
    # or call endpoints at the site root. Host-based routing (django-hosts) can route
    # requests to the wrong urlconf depending on the Host header, causing 404s. Expose
    # the key OTP endpoints at the top-level so client requests reach the view regardless
    # of host routing.
    # Additional aliases for resend-otp (some frontends call it without -login)
    path('client/api/resend-otp/', csrf_exempt(client_auth_views.resend_login_otp_view)),
    path('api/resend-otp/', csrf_exempt(client_auth_views.resend_login_otp_view)),
    path('resend-otp/', csrf_exempt(client_auth_views.resend_login_otp_view)),
    path('client/api/resend-login-otp/', csrf_exempt(client_auth_views.resend_login_otp_view)),
    path('api/resend-login-otp/', csrf_exempt(client_auth_views.resend_login_otp_view)),
    path('resend-login-otp/', csrf_exempt(client_auth_views.resend_login_otp_view)),
    path('client/api/login-otp-status/', csrf_exempt(client_auth_views.login_otp_status_view)),
    path('api/login-otp-status/', csrf_exempt(client_auth_views.login_otp_status_view)),
    path('login-otp-status/', csrf_exempt(client_auth_views.login_otp_status_view)),
    # Verify OTP aliases
    path('client/api/verify-otp/', csrf_exempt(client_auth_views.VerifyOtpView.as_view())),
    path('api/verify-otp/', csrf_exempt(client_auth_views.VerifyOtpView.as_view())),
    path('verify-otp/', csrf_exempt(client_auth_views.VerifyOtpView.as_view())),
    # Status/validate token aliases so client subdomain and root both work
    path('client/api/status/', csrf_exempt(client_auth_views.validate_token_view)),
    path('api/status/', csrf_exempt(client_auth_views.validate_token_view)),
    path('status/', csrf_exempt(client_auth_views.validate_token_view)),
    # Reset-password OTP compatibility aliases (some frontends call without /api/)
    path('client/api/send-reset-otp/', csrf_exempt(client_auth_views.send_reset_otp_view)),
    path('api/send-reset-otp/', csrf_exempt(client_auth_views.send_reset_otp_view)),
    path('send-reset-otp/', csrf_exempt(client_auth_views.send_reset_otp_view)),


    # NOTE: Do not serve `index.html` at project root globally — admin SPA should be accessible
    # only via the `admin` host (handled by django-hosts mapping to adminPanel.urls).
    
    # Chat endpoints (WebSocket handled by ASGI, HTTP fallback handled here)
    path('', include('brokerBackend.chat_urls')),

    # Admin panel routes FIRST to ensure admin API endpoints are not shadowed by client catch-all
    path('', include('adminPanel.urls')),               # Root routes from adminPanel (includes admin API endpoints)
    path('admaan/', include('adminPanel.urls')),        # Alias route for adminPanel
]

# Language-prefixed URL patterns for the client site. This makes URLs like /en/login work.
# We set prefix_default_language=False to avoid forcing the default language prefix.
urlpatterns += i18n_patterns(
    path('', include('clientPanel.urls')),              # Use the correct client urls.py (with /client/api/ and /api/)
    path('', include('clientPanel.urls_new')),          # If you need both, keep both, but client last
    prefix_default_language=False,
)


# Serve static and media files always (for testing or if web server is not configured)
urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

# Custom error handlers
handler404 = 'brokerBackend.views.custom_404'
handler500 = 'brokerBackend.views.custom_500'
handler403 = 'brokerBackend.views.custom_403'
