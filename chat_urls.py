"""
Chat URL patterns for HTTP endpoints and WebSocket routing.
"""

from django.urls import path
from . import chat_views
from adminPanel.views import manager_admin_chat_views

urlpatterns = [
    # Client endpoints
    path('api/chat/send/', chat_views.send_message, name='chat_send_message'),
    path('api/chat/messages/', chat_views.get_messages, name='chat_get_messages'),
    path('api/chat/mark-read/', chat_views.mark_message_as_read, name='chat_mark_read'),
    path('api/chat/client/mark_as_read/', chat_views.mark_client_messages_as_read, name='chat_client_mark_read'),
    path('api/chat/unread-count/', chat_views.get_unread_count, name='chat_unread_count'),
    path('api/chat/delete/<int:message_id>/', chat_views.delete_message, name='chat_delete_message'),
    path('api/chat/status/', chat_views.chat_status, name='chat_status'),
    
    # Admin endpoints
    path('api/chat/admin/send/', chat_views.admin_send_message, name='chat_admin_send'),
    path('api/chat/admin/messages/', chat_views.admin_get_messages, name='chat_admin_messages'),
    path('api/chat/admin/mark_client_as_read/', chat_views.mark_admin_client_messages_as_read, name='chat_admin_mark_client_read'),
    path('api/chat/admin/clear/', chat_views.clear_chat, name='chat_clear'),
    path('api/chat/admin/cleanup/', chat_views.trigger_chat_cleanup, name='chat_admin_cleanup'),
    path('api/chat/admin/stats/', chat_views.get_chat_stats, name='chat_admin_stats'),
    path('api/chat/admin/profiles/', chat_views.get_admin_profiles, name='chat_admin_profiles'),
    path('api/chat/admin/contacts/', chat_views.get_admin_contacts, name='chat_admin_contacts'),
    path('api/chat/admin/managers/', chat_views.get_admin_managers, name='chat_admin_managers'),
    
    # Manager endpoints
    path('api/chat/manager/messages/', manager_admin_chat_views.get_manager_messages, name='chat_manager_messages'),
    path('api/chat/manager/send_message/', manager_admin_chat_views.send_manager_message, name='chat_manager_send'),
    path('api/chat/admin/manager_messages/', manager_admin_chat_views.get_admin_manager_messages, name='chat_admin_manager_messages'),
    path('api/chat/admin/send_to_manager/', manager_admin_chat_views.send_admin_reply_to_manager, name='chat_admin_send_to_manager'),
    path('api/chat/admin/mark_manager_as_read/', manager_admin_chat_views.mark_admin_manager_messages_as_read, name='chat_admin_mark_manager_read'),
    path('api/chat/manager/delete/<int:message_id>/', manager_admin_chat_views.delete_manager_message, name='chat_manager_delete'),
    path('api/chat/manager/mark_as_read/', manager_admin_chat_views.mark_manager_messages_as_read, name='chat_manager_mark_read'),
]
