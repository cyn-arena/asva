from flask import Flask, render_template, request
import os
import hmac
import hashlib
import json
import base64
from dataclasses import dataclass

app = Flask(__name__)

_SIGNING_SECRET = (os.environ.get("SECRET_KEY") or "insecure-deserialization-lab-secret").encode("utf-8")


@dataclass
class User:
    username: str
    is_admin: bool = False


def _sign_payload(payload: bytes) -> str:
    return hmac.new(_SIGNING_SECRET, payload, hashlib.sha256).hexdigest()


def _serialize_user(user: User) -> str:
    payload = json.dumps(
        {
            "username": user.username,
            "is_admin": bool(user.is_admin),
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    token = base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")
    signature = _sign_payload(payload)
    return f"{token}.{signature}"


def _deserialize_user(serialized_data: str) -> User:
    if not isinstance(serialized_data, str):
        raise ValueError("Invalid user data")

    parts = serialized_data.split(".")
    if len(parts) != 2:
        raise ValueError("Invalid user data")

    token, signature = parts
    padding = "=" * (-len(token) % 4)

    try:
        payload = base64.urlsafe_b64decode((token + padding).encode("ascii"))
    except Exception as exc:
        raise ValueError("Invalid user data") from exc

    expected_signature = _sign_payload(payload)
    if not hmac.compare_digest(signature.encode("utf-8"), expected_signature.encode("utf-8")):
        raise ValueError("Invalid user data")

    try:
        data = json.loads(payload.decode("utf-8"))
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

        if isinstance(user, User):
            if user.is_admin:
                message = f"Welcome Admin {user.username}! Here's the secret admin content: ADMIN_KEY_123"
            else:
                message = f"Welcome {user.username}. Only admins can see the secret content."
        else:
            message = "Invalid user data"

        return render_template('result.html', message=message)
    except Exception as e:
        return render_template('result.html', message=f"Error: {str(e)}")


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)