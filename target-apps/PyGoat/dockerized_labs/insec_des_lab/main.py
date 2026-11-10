from flask import Flask, render_template, request
import base64
from dataclasses import dataclass

app = Flask(__name__)

@dataclass
class User:
    username: str
    is_admin: bool = False

def _serialize_user(user: User) -> str:
    username_b64 = base64.b64encode(user.username.encode('utf-8')).decode('ascii')
    return f"{username_b64}.{1 if user.is_admin else 0}"

def _deserialize_user(serialized_data: str) -> User:
    if not isinstance(serialized_data, str):
        raise ValueError("Invalid data")
    parts = serialized_data.split('.')
    if len(parts) != 2:
        raise ValueError("Invalid data")
    username_b64, admin_flag = parts
    if admin_flag not in ('0', '1'):
        raise ValueError("Invalid data")
    username_bytes = base64.b64decode(username_b64.encode('ascii'), validate=True)
    username = username_bytes.decode('utf-8')
    return User(username=username, is_admin=admin_flag == '1')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/serialize', methods=['POST'])
def serialize_data():
    username = request.form.get('username', 'guest')
    user = User(username=username, is_admin=False)
    serialized = _serialize_user(user)
    return render_template('result.html', serialized=serialized)

@app.route('/deserialize', methods=['POST'])
def deserialize_data():
    try:
        serialized_data = request.form.get('serialized_data', '')
        user = _deserialize_user(serialized_data)
        
        if user.is_admin:
            message = f"Welcome Admin {user.username}! Here's the secret admin content: ADMIN_KEY_123"
        else:
            message = f"Welcome {user.username}. Only admins can see the secret content."
        
        return render_template('result.html', message=message)
    except Exception:
        return render_template('result.html', message="Invalid user data")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)