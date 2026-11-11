from flask import Flask, render_template, request
import base64
import json
from dataclasses import dataclass

app = Flask(__name__)

@dataclass
class User:
    username: str
    is_admin: bool = False

def _serialize_user(user: User) -> str:
    payload = json.dumps(
        {
            "username": user.username,
            "is_admin": bool(user.is_admin),
        },
        separators=(",", ":"),
    ).encode("utf-8")
    return base64.b64encode(payload).decode("ascii")

def _deserialize_user(serialized_data: str) -> User:
    if not isinstance(serialized_data, str):
        raise ValueError("Invalid user data")

    try:
        decoded_data = base64.b64decode(serialized_data.encode("ascii"), validate=True)
    except Exception as exc:
        raise ValueError("Invalid user data") from exc

    try:
        data = json.loads(decoded_data.decode("utf-8"))
    except Exception as exc:
        raise ValueError("Invalid user data") from exc

    if not isinstance(data, dict):
        raise ValueError("Invalid user data")

    username = data.get("username")
    if not isinstance(username, str):
        raise ValueError("Invalid user data")

    is_admin = data.get("is_admin", False)
    if not isinstance(is_admin, bool):
        is_admin = False

    return User(username=username, is_admin=is_admin)

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