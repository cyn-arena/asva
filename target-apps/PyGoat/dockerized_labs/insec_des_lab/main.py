from flask import Flask, render_template, request
import os
from dataclasses import dataclass
from itsdangerous import URLSafeSerializer, BadSignature

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "insecure-deserialization-lab-secret")
user_serializer = URLSafeSerializer(app.secret_key, salt="user-data")

@dataclass
class User:
    username: str
    is_admin: bool = False

def _serialize_user(user: User) -> str:
    return user_serializer.dumps({
        "username": user.username,
        "is_admin": bool(user.is_admin),
    })

def _deserialize_user(serialized_data: str) -> User:
    if not isinstance(serialized_data, str):
        raise ValueError("Invalid user data")

    try:
        data = user_serializer.loads(serialized_data)
    except BadSignature as exc:
        raise ValueError("Invalid user data") from exc
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
    except Exception as e:
        return render_template('result.html', message=f"Error: {str(e)}")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)