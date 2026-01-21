"""
WebSocket consumers for real-time chat functionality with database persistence.
"""

from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from django.contrib.auth import get_user_model
import json
import logging
from datetime import datetime
import uuid

logger = logging.getLogger(__name__)
User = get_user_model()


class ChatConsumer(AsyncWebsocketConsumer):
    """Consumer for client-side chat connections."""
    
    async def connect(self):
        try:
            # Get user from scope if authenticated
            self.user = self.scope.get('user')
            self.user_id = str(self.user.id) if self.user and self.user.is_authenticated else str(uuid.uuid4())
            self.room_group_name = f'client_{self.user_id}'
            
            # Join room group
            await self.channel_layer.group_add(
                self.room_group_name,
                self.channel_name
            )
            
            # Also subscribe to general user messages group
            await self.channel_layer.group_add(
                'admin_broadcast',
                self.channel_name
            )
            
            await self.accept()
            
            logger.info(f'User {self.user_id} connected to chat')
            
            # Send welcome message to the user
            await self.send(text_data=json.dumps({
                'type': 'system_message',
                'message': 'Connected to live chat support',
                'timestamp': datetime.now().isoformat(),
                'user_id': self.user_id
            }))
            
            # Notify admins of new user connection
            await self.channel_layer.group_send(
                'admin_chat_room',
                {
                    'type': 'user_connected',
                    'user_id': self.user_id,
                    'user_email': self.user.email if self.user and self.user.is_authenticated else 'Guest',
                    'timestamp': datetime.now().isoformat()
                }
            )
            
        except Exception as e:
            logger.error(f'Error in chat connection: {e}')
            await self.close(code=4000)

    async def disconnect(self, close_code):
        try:
            # Leave room groups
            await self.channel_layer.group_discard(
                self.room_group_name,
                self.channel_name
            )
            await self.channel_layer.group_discard(
                'admin_broadcast',
                self.channel_name
            )
            
            logger.info(f'User {self.user_id} disconnected from chat (code: {close_code})')
            
            # Notify admins of user disconnect
            await self.channel_layer.group_send(
                'admin_chat_room',
                {
                    'type': 'user_disconnected',
                    'user_id': self.user_id,
                    'timestamp': datetime.now().isoformat()
                }
            )
            
        except Exception as e:
            logger.error(f'Error in chat disconnection: {e}')

    async def receive(self, text_data):
        try:
            text_data_json = json.loads(text_data)
            message_type = text_data_json.get('type')
            
            if message_type == 'user_message':
                message = text_data_json['message']
                timestamp = text_data_json.get('timestamp', datetime.now().isoformat())
                
                # Save message to database
                if self.user and self.user.is_authenticated:
                    await self._save_message(
                        sender=self.user,
                        message=message,
                        sender_type='client'
                    )
                
                # Send message to admin room
                await self.channel_layer.group_send(
                    'admin_chat_room',
                    {
                        'type': 'user_message',
                        'message': message,
                        'timestamp': timestamp,
                        'user_id': self.user_id,
                        'sender_email': self.user.email if self.user and self.user.is_authenticated else 'Guest'
                    }
                )
                
                # Echo back to user for confirmation
                await self.send(text_data=json.dumps({
                    'type': 'message_sent',
                    'message': message,
                    'timestamp': timestamp,
                    'status': 'delivered'
                }))
            
            elif message_type == 'user_typing':
                # Notify admin that user is typing
                await self.channel_layer.group_send(
                    'admin_chat_room',
                    {
                        'type': 'user_typing',
                        'user_id': self.user_id,
                        'sender_email': self.user.email if self.user and self.user.is_authenticated else 'Guest'
                    }
                )
            
            elif message_type == 'user_stopped_typing':
                # Notify admin that user stopped typing
                await self.channel_layer.group_send(
                    'admin_chat_room',
                    {
                        'type': 'user_stopped_typing',
                        'user_id': self.user_id,
                        'sender_email': self.user.email if self.user and self.user.is_authenticated else 'Guest'
                    }
                )
                
        except json.JSONDecodeError:
            await self.send(text_data=json.dumps({
                'type': 'error',
                'message': 'Invalid message format'
            }))
        except Exception as e:
            logger.error(f'Error in message handling: {e}')
            await self.send(text_data=json.dumps({
                'type': 'error',
                'message': 'An error occurred while processing your message'
            }))

    async def admin_message(self, event):
        """Receive message from admin and send to client."""
        await self.send(text_data=json.dumps({
            'type': 'admin_message',
            'message': event['message'],
            'sender_name': event.get('sender_name', 'Admin'),
            'timestamp': event.get('timestamp', datetime.now().isoformat()),
            'message_id': event.get('message_id')
        }))

    async def admin_typing(self, event):
        """Admin is typing indicator."""
        await self.send(text_data=json.dumps({
            'type': 'admin_typing'
        }))

    async def admin_stopped_typing(self, event):
        """Admin stopped typing indicator."""
        await self.send(text_data=json.dumps({
            'type': 'admin_stopped_typing'
        }))

    async def broadcast_message(self, event):
        """Broadcast message to all connected users."""
        await self.send(text_data=json.dumps({
            'type': 'broadcast',
            'message': event['message'],
            'timestamp': event.get('timestamp', datetime.now().isoformat())
        }))

    @database_sync_to_async
    def _save_message(self, sender, message, sender_type):
        """Save message to database."""
        try:
            from adminPanel.models import ChatMessage
            ChatMessage.objects.create(
                sender=sender,
                message=message,
                sender_type=sender_type
            )
        except Exception as e:
            logger.error(f'Error saving message to database: {e}')


class AdminChatConsumer(AsyncWebsocketConsumer):
    """Consumer for admin-side chat connections."""
    
    async def connect(self):
        try:
            # Get user from scope
            self.user = self.scope.get('user')
            if not self.user or not self.user.is_authenticated:
                await self.close(code=4001)
                return
            
            self.room_group_name = 'admin_chat_room'
            
            # Join admin room group
            await self.channel_layer.group_add(
                self.room_group_name,
                self.channel_name
            )
            
            await self.accept()
            
            logger.info(f'Admin {self.user.email} connected to chat')
            
            # Send connection confirmation
            await self.send(text_data=json.dumps({
                'type': 'admin_connected',
                'message': 'Admin panel connected',
                'timestamp': datetime.now().isoformat(),
                'admin_email': self.user.email
            }))
            
        except Exception as e:
            logger.error(f'Error in admin chat connection: {e}')
            await self.close(code=4000)

    async def disconnect(self, close_code):
        try:
            logger.info(f'Admin {self.user.email if hasattr(self, "user") else "Unknown"} disconnected from chat (code: {close_code})')
            
            # Leave room group
            await self.channel_layer.group_discard(
                self.room_group_name,
                self.channel_name
            )
        except Exception as e:
            logger.error(f'Error in admin chat disconnect: {e}')

    async def receive(self, text_data):
        try:
            text_data_json = json.loads(text_data)
            message_type = text_data_json.get('type')
            
            if message_type == 'admin_message':
                message = text_data_json['message']
                recipient_id = text_data_json.get('recipient_id')
                timestamp = text_data_json.get('timestamp', datetime.now().isoformat())
                
                # Get recipient user if provided
                recipient = None
                if recipient_id:
                    recipient = await self._get_user(recipient_id)
                
                # Get admin's display name
                admin_sender_name = f"{self.user.first_name} {self.user.last_name}".strip() or self.user.email
                
                # Save message to database
                message_obj = await self._save_admin_message(
                    sender=self.user,
                    recipient=recipient,
                    message=message,
                    admin_sender_name=admin_sender_name
                )
                
                # If specific recipient, send to their room
                if recipient_id:
                    await self.channel_layer.group_send(
                        f'client_{recipient_id}',
                        {
                            'type': 'admin_message',
                            'message': message,
                            'sender_name': admin_sender_name,
                            'timestamp': timestamp,
                            'message_id': message_obj.id if message_obj else None
                        }
                    )
                    
                    # Broadcast admin message to all other admins so they see the reply
                    await self.channel_layer.group_send(
                        'admin_chat_room',
                        {
                            'type': 'admin_message_broadcast',
                            'message': message,
                            'recipient_id': recipient_id,
                            'sender_name': admin_sender_name,
                            'sender_id': self.user.id,
                            'timestamp': timestamp,
                            'message_id': message_obj.id if message_obj else None
                        }
                    )
                else:
                    # Broadcast to all users
                    await self.channel_layer.group_send(
                        'admin_broadcast',
                        {
                            'type': 'broadcast_message',
                            'message': message,
                            'timestamp': timestamp,
                            'sender': self.user.email
                        }
                    )
                
                # Confirm to admin
                await self.send(text_data=json.dumps({
                    'type': 'message_sent',
                    'message': message,
                    'timestamp': timestamp,
                    'status': 'delivered',
                    'recipient': recipient_id or 'all'
                }))
            
            elif message_type == 'admin_typing':
                recipient_id = text_data_json.get('recipient_id')
                if recipient_id:
                    await self.channel_layer.group_send(
                        f'client_{recipient_id}',
                        {
                            'type': 'admin_typing'
                        }
                    )
            
            elif message_type == 'admin_stopped_typing':
                recipient_id = text_data_json.get('recipient_id')
                if recipient_id:
                    await self.channel_layer.group_send(
                        f'client_{recipient_id}',
                        {
                            'type': 'admin_stopped_typing'
                        }
                    )
                
        except json.JSONDecodeError:
            await self.send(text_data=json.dumps({
                'type': 'error',
                'message': 'Invalid message format'
            }))
        except Exception as e:
            logger.error(f'Error in admin message handling: {e}')
            await self.send(text_data=json.dumps({
                'type': 'error',
                'message': 'An error occurred while processing the admin message'
            }))

    async def user_message(self, event):
        """Receive message from user and send to admin."""
        await self.send(text_data=json.dumps({
            'type': 'user_message',
            'message': event['message'],
            'user_id': event['user_id'],
            'sender_email': event.get('sender_email', 'Unknown'),
            'timestamp': event.get('timestamp', datetime.now().isoformat())
        }))

    async def admin_message_broadcast(self, event):
        """Receive admin message from another admin and broadcast to all admins."""
        await self.send(text_data=json.dumps({
            'type': 'admin_message_broadcast',
            'message': event['message'],
            'recipient_id': event['recipient_id'],
            'sender_name': event.get('sender_name', 'Unknown Admin'),
            'sender_id': event.get('sender_id'),
            'timestamp': event.get('timestamp', datetime.now().isoformat()),
            'message_id': event.get('message_id')
        }))

    async def user_typing(self, event):
        """User is typing indicator."""
        await self.send(text_data=json.dumps({
            'type': 'user_typing',
            'user_id': event['user_id'],
            'sender_email': event.get('sender_email', 'Unknown')
        }))

    async def user_stopped_typing(self, event):
        """User stopped typing indicator."""
        await self.send(text_data=json.dumps({
            'type': 'user_stopped_typing',
            'user_id': event['user_id'],
            'sender_email': event.get('sender_email', 'Unknown')
        }))

    async def user_connected(self, event):
        """User connected to chat."""
        await self.send(text_data=json.dumps({
            'type': 'user_connected',
            'user_id': event['user_id'],
            'user_email': event.get('user_email', 'Unknown'),
            'timestamp': event.get('timestamp', datetime.now().isoformat())
        }))

    async def user_disconnected(self, event):
        """User disconnected from chat."""
        await self.send(text_data=json.dumps({
            'type': 'user_disconnected',
            'user_id': event['user_id'],
            'timestamp': event.get('timestamp', datetime.now().isoformat())
        }))

    @database_sync_to_async
    def _save_admin_message(self, sender, recipient, message, admin_sender_name=None):
        """Save admin message to database."""
        try:
            from adminPanel.models import ChatMessage
            return ChatMessage.objects.create(
                sender=sender,
                recipient=recipient,
                message=message,
                sender_type='admin',
                admin_sender_name=admin_sender_name
            )
        except Exception as e:
            logger.error(f'Error saving admin message to database: {e}')
            return None

    @database_sync_to_async
    def _get_user(self, user_id):
        """Get user by ID."""
        try:
            return User.objects.get(id=user_id)
        except User.DoesNotExist:
            return None