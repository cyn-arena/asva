from flask import Flask, render_template, request, make_response
import json
import base64
from dataclasses import dataclass

app = Flask(__name__)

@dataclass
class User:
    username: str 
    is_admin: bool = False

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/serialize', methods=['POST'])
def serialize_data():
    username = request.form.get('username', 'guest')
    # Create regular user with admin=False
    user = User(username=username, is_admin=False)
    # Use safe JSON serialization instead of pickle
    serialized = base64.b64encode(
        json.dumps({
            "username": user.username,
            "is_admin": user.is_admin,
        }).encode()
    ).decode()
    return render_template('result.html', serialized=serialized)

@app.route('/deserialize', methods=['POST'])
def deserialize_data():
    try:
        serialized_data = request.form.get('serialized_data', '')
        decoded_data = base64.b64decode(serialized_data).decode()
        data = json.loads(decoded_data)
        if not isinstance(data, dict) or not isinstance(data.get('username'), str) or not isinstance(data.get('is_admin'), bool):
            message = "Invalid user data"
        else:
            user = User(username=data['username'], is_admin=data['is_admin'])
            if user.is_admin:
                message = f"Welcome Admin {user.username}! Here's the secret admin content: ADMIN_KEY_123"
            else:
                message = f"Welcome {user.username}. Only admins can see the secret content."
        return render_template('result.html', message=message)
    except Exception as e:
        return render_template('result.html', message=f"Error: {str(e)}")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)