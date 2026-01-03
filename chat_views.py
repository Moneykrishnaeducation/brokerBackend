"""
Chat views for HTTP fallback functionality.
"""

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from adminPanel.permissions import IsAdminOrManager
import json
from datetime import datetime

# Simple in-memory storage for messages (replace with database in production)
messages = []
active_users = set()

@csrf_exempt
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def send_message(request):
    """
    HTTP endpoint for sending messages when WebSocket is not available.
    """
    try:
        data = request.data
        message = data.get('message', '').strip()
        message_type = data.get('type', 'user_message')
        timestamp = data.get('timestamp', datetime.now().isoformat())
        
        if not message:
            return JsonResponse({'status': 'error', 'message': 'Message cannot be empty'})
        
        # Store the message
        message_data = {
            'id': len(messages) + 1,
            'message': message,
            'type': message_type,
            'timestamp': timestamp,
            'sender': 'user' if message_type == 'user_message' else 'admin',
            'user_id': request.user.id,
            'username': request.user.username
        }
        
        messages.append(message_data)
        
        return JsonResponse({
            'status': 'success',
            'message_id': message_data['id'],
            'timestamp': timestamp
        })
        
    except json.JSONDecodeError:
        return JsonResponse({'status': 'error', 'message': 'Invalid JSON format'})
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)})

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_messages(request):
    """
    HTTP endpoint for retrieving messages when WebSocket is not available.
    """
    try:
        # Support both 'last_id' and 'since_id' parameters for compatibility
        last_id = int(request.GET.get('last_id', request.GET.get('since_id', 0)))
        
        # Return messages after the specified ID
        new_messages = [msg for msg in messages if msg['id'] > last_id]
        
        return JsonResponse({
            'status': 'success',
            'messages': new_messages,
            'last_id': messages[-1]['id'] if messages else 0
        })
        
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)})

@csrf_exempt
@api_view(['POST'])
@permission_classes([IsAuthenticated, IsAdminOrManager])
def admin_send_message(request):
    """
    HTTP endpoint for admin to send messages when WebSocket is not available.
    """
    try:
        data = request.data
        message = data.get('message', '').strip()
        timestamp = data.get('timestamp', datetime.now().isoformat())
        
        if not message:
            return JsonResponse({'status': 'error', 'message': 'Message cannot be empty'})
        
        # Store the admin message
        message_data = {
            'id': len(messages) + 1,
            'message': message,
            'type': 'admin_message',
            'timestamp': timestamp,
            'sender': 'admin',
            'user_id': request.user.id,
            'username': request.user.username
        }
        
        messages.append(message_data)
        
        return JsonResponse({
            'status': 'success',
            'message_id': message_data['id'],
            'timestamp': timestamp
        })
        
    except json.JSONDecodeError:
        return JsonResponse({'status': 'error', 'message': 'Invalid JSON format'})
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)})

@csrf_exempt
@api_view(['POST'])
@permission_classes([IsAuthenticated, IsAdminOrManager])
def clear_chat(request):
    """
    HTTP endpoint for clearing chat history (admin only).
    """
    try:
        global messages
        messages = []
        
        return JsonResponse({
            'status': 'success',
            'message': 'Chat history cleared'
        })
        
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)})

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def chat_status(request):
    """
    HTTP endpoint for getting chat status and connection info.
    """
    return JsonResponse({
        'status': 'success',
        'websocket_available': True,
        'message_count': len(messages),
        'active_users': len(active_users)
    })
