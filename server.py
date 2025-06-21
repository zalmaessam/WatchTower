from flask import Flask, request
from flask_socketio import SocketIO, emit
from datetime import datetime
import json

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

# Store connected users and their session IDs
connected_users = {}

@socketio.on('connect')
def handle_connect():
    print("✅ Client connected")

@socketio.on('disconnect')
def handle_disconnect():
    # Remove user from connected_users
    username = None
    for user, sid in connected_users.items():
        if sid == request.sid:
            username = user
            break
    if username:
        del connected_users[username]
    print(f"❌ Client disconnected: {username}")

@socketio.on('login')
def handle_login(data):
    username = data.get('username')
    if username:
        connected_users[username] = request.sid
        print(f"👤 User logged in: {username}")

@socketio.on('message')
def handle_message(data):
    try:
        # Add timestamp if not present
        if 'timestamp' not in data:
            data['timestamp'] = datetime.now().strftime("%I:%M %p")
        
        # Get recipient's session ID
        recipient_sid = connected_users.get(data['to'])
        
        # Emit to recipient if online
        if recipient_sid:
            emit('new_message', data, room=recipient_sid)
        
        # Also emit back to sender for confirmation
        emit('new_message', data, room=request.sid)
        
        print(f"📨 Message from {data['from']} to {data['to']}")
    except Exception as e:
        print(f"❌ Error handling message: {e}")
        emit('error', {'message': str(e)}, room=request.sid)

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=False) 