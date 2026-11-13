from flask import Flask, render_template, request
import base64
import json
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
    user = User(username=username, is_admin=False)
    serialized = base64.b64encode(
        json.dumps(
            {"username": user.username, "is_admin": user.is_admin}
        ).encode('utf-8')
    ).decode('ascii')
    return render_template('result.html', serialized=serialized)

@app.route('/deserialize', methods=['POST'])
def deserialize_data():
    try:
        serialized_data = request.form.get('serialized_data', '')
        decoded_data = base64.b64decode(serialized_data)
        data = json.loads(decoded_data.decode('utf-8'))

        if not isinstance(data, dict):
            raise ValueError("Invalid user data")

        username = data.get('username')
        if not isinstance(username, str):
            raise ValueError("Invalid user data")

        is_admin = data.get('is_admin', False)
        if not isinstance(is_admin, bool):
            is_admin = False

        user = User(username=username, is_admin=is_admin)

        if user.is_admin:
            message = f"Welcome Admin {user.username}! Here's the secret admin content: ADMIN_KEY_123"
        else:
            message = f"Welcome {user.username}. Only admins can see the secret content."

        return render_template('result.html', message=message)
    except Exception as e:
        return render_template('result.html', message=f"Error: {str(e)}")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)