"""
Chat URL patterns for HTTP fallback and WebSocket endpoints.
"""

from django.urls import path
from . import chat_views

urlpatterns = [
    # HTTP fallback endpoints
    path('api/chat/send/', chat_views.send_message, name='chat_send_message'),
    path('api/chat/messages/', chat_views.get_messages, name='chat_get_messages'),
    path('api/chat/admin/send/', chat_views.admin_send_message, name='chat_admin_send'),
    path('api/chat/admin/clear/', chat_views.clear_chat, name='chat_clear'),
    path('api/chat/status/', chat_views.chat_status, name='chat_status'),
]
