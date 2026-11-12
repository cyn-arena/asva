from flask import Flask, render_template, request
import base64
import hashlib
import hmac
import json
import os
from dataclasses import dataclass

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "insecure-deserialization-lab-secret")
_SIGNING_KEY = app.secret_key.encode("utf-8")

@dataclass
class User:
    username: str
    is_admin: bool = False

def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)

def _sign_payload(payload_b64: str) -> str:
    return hmac.new(
        _SIGNING_KEY,
        payload_b64.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()

def _serialize_user(user: User) -> str:
    payload = json.dumps(
        {
            "username": user.username,
            "is_admin": bool(user.is_admin),
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    payload_b64 = _b64url_encode(payload)
    signature = _sign_payload(payload_b64)
    return f"{payload_b64}.{signature}"

def _deserialize_user(serialized_data: str) -> User:
    if not isinstance(serialized_data, str):
        raise ValueError("Invalid user data")

    parts = serialized_data.split(".", 1)
    if len(parts) != 2:
        raise ValueError("Invalid user data")

    payload_b64, signature = parts

    try:
        expected_signature = _sign_payload(payload_b64)
    except UnicodeEncodeError as exc:
        raise ValueError("Invalid user data") from exc

    if not hmac.compare_digest(signature, expected_signature):
        raise ValueError("Invalid user data")

    try:
        decoded_data = _b64url_decode(payload_b64)
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
        raise ValueError("Invalid user data")

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
    except Exception as e:
        return render_template('result.html', message=f"Error: {str(e)}")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)