"""
WebSocket consumers for real-time chat functionality with improved error handling.
"""

from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
import json
import logging
from datetime import datetime
import uuid

logger = logging.getLogger(__name__)

class ChatConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        try:
            # Generate a unique user ID for this connection
            self.user_id = str(uuid.uuid4())
            self.room_group_name = 'chat_room'
            
            # Join room group
            await self.channel_layer.group_add(
                self.room_group_name,
                self.channel_name
            )
            
            # Accept the connection
            await self.accept()
            
            logger.info(f'User {self.user_id} connected to chat')
            
            # Send welcome message to the user
            await self.send(text_data=json.dumps({
                'type': 'system_message',
                'message': 'Connected to live chat support',
                'timestamp': datetime.now().isoformat(),
                'user_id': self.user_id
            }))
            
            # Notify admins of new user
            await self.channel_layer.group_send(
                'admin_chat_room',
                {
                    'type': 'user_connected',
                    'user_id': self.user_id,
                    'active_users': await self.get_active_users_count()
                }
            )
            
        except Exception as e:
            logger.error(f'Error in chat connection: {e}')
            await self.close(code=4000)

    async def disconnect(self, close_code):
        try:
            # Leave room group
            await self.channel_layer.group_discard(
                self.room_group_name,
                self.channel_name
            )
            
            logger.info(f'User {self.user_id} disconnected from chat')
            
            # Notify admins of user disconnect
            await self.channel_layer.group_send(
                'admin_chat_room',
                {
                    'type': 'user_disconnected',
                    'user_id': self.user_id,
                    'active_users': await self.get_active_users_count()
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
                
                # Send message to admin room
                await self.channel_layer.group_send(
                    'admin_chat_room',
                    {
                        'type': 'user_message',
                        'message': message,
                        'timestamp': timestamp,
                        'user_id': self.user_id
                    }
                )
                
                # Echo back to user for confirmation
                await self.send(text_data=json.dumps({
                    'type': 'message_sent',
                    'message': message,
                    'timestamp': timestamp,
                    'status': 'delivered'
                }))
                
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
        # Send message from admin to user
        await self.send(text_data=json.dumps({
            'type': 'admin_message',
            'message': event['message'],
            'timestamp': event['timestamp']
        }))

    async def admin_typing(self, event):
        await self.send(text_data=json.dumps({
            'type': 'admin_typing'
        }))

    async def admin_stopped_typing(self, event):
        await self.send(text_data=json.dumps({
            'type': 'admin_stopped_typing'
        }))

    async def get_active_users_count(self):
        # TODO: Implement proper user counting logic
        # For now, return a placeholder value
        return 1


class AdminChatConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        try:
            self.room_group_name = 'admin_chat_room'
            
            # Join admin room group
            await self.channel_layer.group_add(
                self.room_group_name,
                self.channel_name
            )
            
            await self.accept()
            
            logger.info('Admin connected to chat')
            
            # Send connection confirmation
            await self.send(text_data=json.dumps({
                'type': 'admin_connected',
                'message': 'Admin panel connected',
                'timestamp': datetime.now().isoformat()
            }))
            
        except Exception as e:
            logger.error(f'Error in admin chat connection: {e}')
            await self.close(code=4000)

    async def disconnect(self, close_code):
        try:
            logger.info(f'Admin disconnected from chat (code: {close_code})')
            
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
                timestamp = text_data_json.get('timestamp', datetime.now().isoformat())
                
                # Send message to all users
                await self.channel_layer.group_send(
                    'chat_room',
                    {
                        'type': 'admin_message',
                        'message': message,
                        'timestamp': timestamp
                    }
                )
                
                # Confirm to admin
                await self.send(text_data=json.dumps({
                    'type': 'message_sent',
                    'message': message,
                    'timestamp': timestamp,
                    'status': 'delivered'
                }))
            
            elif message_type == 'admin_typing':
                await self.channel_layer.group_send(
                    'chat_room',
                    {
                        'type': 'admin_typing'
                    }
                )
            
            elif message_type == 'admin_stopped_typing':
                await self.channel_layer.group_send(
                    'chat_room',
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
        # Send user message to admin
        await self.send(text_data=json.dumps({
            'type': 'user_message',
            'message': event['message'],
            'timestamp': event['timestamp'],
            'user_id': event['user_id']
        }))

    async def user_connected(self, event):
        await self.send(text_data=json.dumps({
            'type': 'user_connected',
            'user_id': event['user_id'],
            'active_users': event['active_users']
        }))

    async def user_disconnected(self, event):
        await self.send(text_data=json.dumps({
            'type': 'user_disconnected',
            'user_id': event['user_id'],
            'active_users': event['active_users']
        }))
