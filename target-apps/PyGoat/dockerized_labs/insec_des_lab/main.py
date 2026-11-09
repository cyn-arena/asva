from flask import Flask, render_template, request
import base64
import hashlib
import hmac
import json
import os
from dataclasses import dataclass

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key-change-me")

@dataclass
class User:
    username: str
    is_admin: bool = False

def _sign_payload(payload: bytes) -> str:
    secret = app.secret_key
    if isinstance(secret, str):
        secret = secret.encode("utf-8")
    return hmac.new(secret, payload, hashlib.sha256).hexdigest()

def _serialize_user(user: User) -> str:
    payload = json.dumps(
        {"username": user.username, "is_admin": bool(user.is_admin)},
        separators=(",", ":"),
    ).encode("utf-8")
    token = base64.b64encode(payload).decode("ascii")
    signature = _sign_payload(payload)
    return f"{token}.{signature}"

def _deserialize_user(serialized_data: str) -> User:
    token, signature = serialized_data.split(".", 1)
    payload = base64.b64decode(token.encode("ascii"), validate=True)
    expected_signature = _sign_payload(payload)
    if not hmac.compare_digest(expected_signature, signature):
        raise ValueError("Invalid signature")

    data = json.loads(payload.decode("utf-8"))
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