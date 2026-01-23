"""
Chat views for HTTP endpoints and chat message management.
"""

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.db.models import Q
from rest_framework.decorators import api_view, permission_classes, throttle_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from adminPanel.permissions import IsAdminOrManager, IsAdmin
from adminPanel.models import ChatMessage
from adminPanel.serializers import ChatMessageSerializer
from django.contrib.auth import get_user_model
import json
from datetime import datetime
import logging

logger = logging.getLogger(__name__)
User = get_user_model()


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def send_message(request):
    """
    Send a chat message from client to admin (supports text and/or image).
    """
    try:
        data = request.data
        message_text = data.get('message', '').strip()
        image_file = request.FILES.get('image')
        
        # Allow message with text, image, or both
        if not message_text and not image_file:
            return Response(
                {'status': 'error', 'message': 'Message or image is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Create the chat message
        chat_message = ChatMessage.objects.create(
            sender=request.user,
            message=message_text,
            image=image_file if image_file else None,
            sender_type='client'
        )
        
        serializer = ChatMessageSerializer(chat_message)
        
        return Response({
            'status': 'success',
            'message_id': chat_message.id,
            'data': serializer.data
        }, status=status.HTTP_201_CREATED)
        
    except Exception as e:
        logger.error(f'Error sending message: {e}')
        return Response(
            {'status': 'error', 'message': str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['GET'])
@permission_classes([IsAuthenticated])
@throttle_classes([])
def get_messages(request):
    """
    Retrieve chat messages for the authenticated user.
    Supports pagination with 'last_id' parameter.
    """
    try:
        user = request.user
        last_id = int(request.GET.get('last_id', 0))
        limit = int(request.GET.get('limit', 50))
        
        # Get messages where user is sender (only client messages, not admin messages) or recipient
        messages_queryset = ChatMessage.objects.filter(
            Q(sender=user, sender_type='client') | Q(recipient=user)
        ).filter(id__gt=last_id).order_by('created_at')
        
        # Get the last ID before slicing
        last_message_id = messages_queryset.values_list('id', flat=True).last() if messages_queryset.exists() else last_id
        
        # Now slice to get the limit
        messages = messages_queryset[:limit]
        
        serializer = ChatMessageSerializer(messages, many=True)
        
        return Response({
            'status': 'success',
            'messages': serializer.data,
            'last_id': last_message_id,
            'count': len(serializer.data)
        })
        
    except Exception as e:
        logger.error(f'Error retrieving messages: {e}')
        return Response(
            {'status': 'error', 'message': str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@permission_classes([IsAuthenticated, IsAdmin])
def admin_send_message(request):
    """
    Admin endpoint to send messages to clients (supports text and/or image).
    """
    try:
        data = request.data
        message_text = data.get('message', '').strip()
        recipient_id = data.get('recipient_id')
        image_file = request.FILES.get('image')
        
        # Allow message with text, image, or both
        if not message_text and not image_file:
            return Response(
                {'status': 'error', 'message': 'Message or image is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Get recipient if provided
        recipient = None
        if recipient_id:
            try:
                recipient = User.objects.get(id=recipient_id)
            except User.DoesNotExist:
                return Response(
                    {'status': 'error', 'message': 'Recipient not found'},
                    status=status.HTTP_404_NOT_FOUND
                )
        
        # Get admin's display name
        admin_sender_name = f"{request.user.first_name} {request.user.last_name}".strip() or request.user.email
        
        # Create the chat message
        chat_message = ChatMessage.objects.create(
            sender=request.user,
            recipient=recipient,
            message=message_text,
            image=image_file if image_file else None,
            sender_type='admin',
            admin_sender_name=admin_sender_name
        )
        
        serializer = ChatMessageSerializer(chat_message)
        
        return Response({
            'status': 'success',
            'message_id': chat_message.id,
            'data': serializer.data
        }, status=status.HTTP_201_CREATED)
        
    except Exception as e:
        logger.error(f'Error in admin send message: {e}')
        return Response(
            {'status': 'error', 'message': str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['GET'])
@permission_classes([IsAuthenticated, IsAdmin])
@throttle_classes([])
def admin_get_messages(request):
    """
    Admin endpoint to retrieve all messages or messages from a specific user.
    Shows all messages (from client and all admins) for a specific client.
    """
    try:
        user_id = request.GET.get('user_id')
        last_id = int(request.GET.get('last_id', 0))
        limit = int(request.GET.get('limit', 50))
        
        if user_id:
            # Get conversation with specific user (client)
            try:
                target_user = User.objects.get(id=user_id)
            except User.DoesNotExist:
                return Response(
                    {'status': 'error', 'message': 'User not found'},
                    status=status.HTTP_404_NOT_FOUND
                )
            
            # Get ALL messages for this client conversation:
            # 1. Messages FROM the client (to any admin)
            # 2. Messages FROM any admin TO this specific client
            # This ensures all admins viewing the same client see all replies
            # EXCLUDE: Messages from other clients
            messages_queryset = ChatMessage.objects.filter(
                Q(sender=target_user, sender_type='client') |  # Messages sent BY this client
                Q(recipient=target_user, sender_type='admin')  # Messages sent BY any admin TO this client
            ).filter(id__gt=last_id).order_by('created_at')
        else:
            # Get all messages sent to this admin OR messages from clients (but not sent by this admin)
            messages_queryset = ChatMessage.objects.filter(
                Q(recipient=request.user) | Q(sender_type='client', recipient__isnull=True)
            ).filter(id__gt=last_id).order_by('-created_at')
        
        # Get the last ID before slicing
        last_message_id = messages_queryset.values_list('id', flat=True).last() if messages_queryset.exists() else last_id
        
        # Now slice to get the limit
        messages = messages_queryset[:limit]
        
        serializer = ChatMessageSerializer(messages, many=True)
        
        return Response({
            'status': 'success',
            'messages': serializer.data,
            'last_id': last_message_id,
            'count': len(serializer.data)
        })
        
    except Exception as e:
        logger.error(f'Error retrieving admin messages: {e}')
        return Response(
            {'status': 'error', 'message': str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def mark_client_messages_as_read(request):
    """
    Mark all unread messages from a specific client as read (for admin viewing).
    """
    try:
        client_id = request.data.get('client_id')
        
        try:
            client = User.objects.get(id=client_id)
        except User.DoesNotExist:
            return Response(
                {'status': 'error', 'message': 'Client not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Mark all unread messages from this client as read
        updated_count = ChatMessage.objects.filter(
            sender=client,
            is_read=False
        ).update(is_read=True)
        
        return Response({
            'status': 'success',
            'message': f'Marked {updated_count} messages as read'
        })
        
    except Exception as e:
        logger.error(f'Error marking client messages as read: {e}')
        return Response(
            {'status': 'error', 'message': str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def mark_message_as_read(request):
    """
    Mark a message as read.
    """
    try:
        message_id = request.data.get('message_id')
        
        try:
            message = ChatMessage.objects.get(id=message_id)
            # Only mark as read if user is the recipient
            if message.recipient == request.user or message.sender == request.user:
                message.is_read = True
                message.save()
                
                return Response({
                    'status': 'success',
                    'message': 'Message marked as read'
                })
            else:
                return Response(
                    {'status': 'error', 'message': 'Unauthorized'},
                    status=status.HTTP_403_FORBIDDEN
                )
        except ChatMessage.DoesNotExist:
            return Response(
                {'status': 'error', 'message': 'Message not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        
    except Exception as e:
        logger.error(f'Error marking message as read: {e}')
        return Response(
            {'status': 'error', 'message': str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_unread_count(request):
    """
    Get unread message count for the authenticated user.
    """
    try:
        unread_count = ChatMessage.objects.filter(
            recipient=request.user,
            is_read=False
        ).count()
        
        return Response({
            'status': 'success',
            'unread_count': unread_count
        })
        
    except Exception as e:
        logger.error(f'Error getting unread count: {e}')
        return Response(
            {'status': 'error', 'message': str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@permission_classes([IsAuthenticated, IsAdmin])
def clear_chat(request):
    """
    Clear chat history (admin only).
    """
    try:
        user_id = request.data.get('user_id')
        
        if user_id:
            # Clear chat with specific user
            try:
                target_user = User.objects.get(id=user_id)
                ChatMessage.objects.filter(
                    Q(sender=target_user) | Q(sender=request.user, recipient=target_user)
                ).delete()
            except User.DoesNotExist:
                return Response(
                    {'status': 'error', 'message': 'User not found'},
                    status=status.HTTP_404_NOT_FOUND
                )
        else:
            # Clear all chat
            ChatMessage.objects.all().delete()
        
        return Response({
            'status': 'success',
            'message': 'Chat history cleared'
        })
        
    except Exception as e:
        logger.error(f'Error clearing chat: {e}')
        return Response(
            {'status': 'error', 'message': str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def chat_status(request):
    """
    Get chat status and statistics.
    """
    try:
        user_message_count = ChatMessage.objects.filter(sender=request.user).count()
        unread_count = ChatMessage.objects.filter(recipient=request.user, is_read=False).count()
        
        return Response({
            'status': 'success',
            'message_count': user_message_count,
            'unread_count': unread_count,
            'websocket_available': True
        })
        
    except Exception as e:
        logger.error(f'Error getting chat status: {e}')
        return Response(
            {'status': 'error', 'message': str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_message(request, message_id):
    """
    Delete a chat message (only by sender or admin).
    """
    try:
        try:
            message = ChatMessage.objects.get(id=message_id)
        except ChatMessage.DoesNotExist:
            return Response(
                {'status': 'error', 'message': 'Message not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Check if user is the sender or an admin
        is_admin = request.user.is_staff or (hasattr(request.user, 'manager_admin_status') and request.user.manager_admin_status)
        is_sender = message.sender == request.user
        
        if not (is_sender or is_admin):
            return Response(
                {'status': 'error', 'message': 'You can only delete your own messages'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        message.delete()
        
        return Response({
            'status': 'success',
            'message': 'Message deleted successfully'
        })
        
    except Exception as e:
        logger.error(f'Error deleting message: {e}')
        return Response(
            {'status': 'error', 'message': str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@permission_classes([IsAuthenticated, IsAdmin])
def trigger_chat_cleanup(request):
    """
    Manually trigger the cleanup of old chat messages (admin only).
    Deletes messages older than 24 hours by default.
    """
    try:
        # Check if user is admin
        is_admin = request.user.is_staff or (hasattr(request.user, 'manager_admin_status') and request.user.manager_admin_status)
        
        if not is_admin:
            return Response(
                {'status': 'error', 'message': 'Only admins can trigger chat cleanup'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Get hours parameter from request
        hours = request.data.get('hours', 24)
        
        # Import and run the cleanup task using background thread
        from adminPanel.chat_cleanup_thread import chat_cleanup_thread
        
        result = chat_cleanup_thread.force_cleanup(hours=hours)
        
        return Response(result)
        
    except Exception as e:
        logger.error(f'Error triggering chat cleanup: {e}')
        return Response(
            {'status': 'error', 'message': str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def mark_client_messages_as_read(request):
    """
    Client endpoint to mark all their unread messages from admin as read.
    """
    try:
        # Mark all messages from admin to this client as read
        ChatMessage.objects.filter(
            recipient=request.user,
            sender_type='admin',
            is_read=False
        ).update(is_read=True)
        
        return Response({
            'status': 'success',
            'message': 'Messages marked as read'
        })
        
    except Exception as e:
        logger.error(f'Error marking messages as read: {e}')
        return Response(
            {'status': 'error', 'message': str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@permission_classes([IsAuthenticated, IsAdmin])
def mark_admin_client_messages_as_read(request):
    """
    Admin endpoint to mark all messages to a specific client as read.
    """
    try:
        client_id = request.data.get('client_id')
        
        if not client_id:
            return Response(
                {'status': 'error', 'message': 'client_id is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            client = User.objects.get(id=client_id)
        except User.DoesNotExist:
            return Response(
                {'status': 'error', 'message': 'Client not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Mark all messages sent by the client to this admin as read
        ChatMessage.objects.filter(
            sender=client,
            recipient=request.user,
            is_read=False
        ).update(is_read=True)
        
        # Also mark general messages from this client as read
        ChatMessage.objects.filter(
            sender=client,
            recipient__isnull=True,
            is_read=False
        ).update(is_read=True)
        
        return Response({
            'status': 'success',
            'message': 'Client messages marked as read'
        })
        
    except Exception as e:
        logger.error(f'Error marking admin client messages as read: {e}')
        return Response(
            {'status': 'error', 'message': str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_chat_stats(request):
    """
    Get chat statistics including total messages and cleanup info.
    """
    try:
        from django.utils import timezone
        from datetime import timedelta
        
        total_messages = ChatMessage.objects.count()
        messages_24h = ChatMessage.objects.filter(
            created_at__gte=timezone.now() - timedelta(hours=24)
        ).count()
        messages_7d = ChatMessage.objects.filter(
            created_at__gte=timezone.now() - timedelta(days=7)
        ).count()
        
        # Get oldest message
        oldest_message = ChatMessage.objects.order_by('created_at').first()
        oldest_created = oldest_message.created_at if oldest_message else None
        
        return Response({
            'status': 'success',
            'stats': {
                'total_messages': total_messages,
                'messages_in_last_24h': messages_24h,
                'messages_in_last_7d': messages_7d,
                'oldest_message_created': oldest_created.isoformat() if oldest_created else None,
                'cleanup_frequency': 'Every hour (removes messages older than 24 hours)',
                'next_cleanup_info': 'Automatically triggered by Celery Beat'
            }
        })
        
    except Exception as e:
        logger.error(f'Error getting chat stats: {e}')
        return Response(
            {'status': 'error', 'message': str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['GET'])
@permission_classes([IsAuthenticated, IsAdminOrManager])
def get_admin_profiles(request):
    """
    Admin endpoint to retrieve profile pictures for multiple admins.
    Query parameter: ids (comma-separated user IDs)
    Returns: {profiles: [{id: int, profile_pic: string|null}]}
    """
    try:
        ids_param = request.GET.get('ids', '')
        
        if not ids_param:
            return Response(
                {'status': 'error', 'message': 'ids parameter required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Parse comma-separated IDs
        try:
            admin_ids = [int(id_str.strip()) for id_str in ids_param.split(',') if id_str.strip()]
        except ValueError:
            return Response(
                {'status': 'error', 'message': 'Invalid ID format'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        if not admin_ids:
            return Response({'profiles': []})
        
        # Get admins with their profile pictures
        admins = User.objects.filter(id__in=admin_ids).values('id', 'profile_pic')
        
        return Response({
            'profiles': [
                {
                    'id': admin['id'],
                    'profile_pic': admin['profile_pic'] if admin['profile_pic'] else None
                }
                for admin in admins
            ]
        })
        
    except Exception as e:
        logger.error(f'Error getting admin profiles: {e}')
        return Response(
            {'status': 'error', 'message': str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
