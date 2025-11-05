from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import jwt, datetime, random
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

JWT_SECRET = "change_this_super_secret_in_prod"
JWT_ALGO = "HS256"
JWT_EXP_MINUTES = 60

# In-memory user database
USERS = {
    "admin": {"password_hash": generate_password_hash("adminpass"), "role": "admin"},
    "user": {"password_hash": generate_password_hash("userpass"), "role": "user"}
}

# Temporary OTP store {username: otp}
OTP_STORE = {}

# JWT helpers
def create_token(username, role):
    payload = {
        "sub": username,
        "role": role,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=JWT_EXP_MINUTES)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)

def decode_token(token):
    return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])

# Auth decorators
def auth_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "Missing Bearer token"}), 401
        token = auth.split()[1]
        try:
            payload = decode_token(token)
            request.user = payload
        except Exception as e:
            return jsonify({"error": "Invalid or expired token", "detail": str(e)}), 401
        return f(*args, **kwargs)
    return wrapper

def role_required(role):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if request.user.get("role") != role:
                return jsonify({"error": "Forbidden"}), 403
            return f(*args, **kwargs)
        return wrapper
    return decorator

# Routes
@app.route("/register", methods=["POST"])
def register():
    data = request.json
    username, password = data.get("username"), data.get("password")
    if username in USERS:
        return jsonify({"error": "User exists"}), 400
    USERS[username] = {"password_hash": generate_password_hash(password), "role": "user"}
    return jsonify({"ok": True, "msg": "User registered"})

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username, password = data.get("username"), data.get("password")
    user = USERS.get(username)
    if not user or not check_password_hash(user["password_hash"], password):
        return jsonify({"error": "Invalid credentials"}), 401

    # Generate OTP
    otp = str(random.randint(100000, 999999))
    OTP_STORE[username] = otp
    return jsonify({"msg": f"OTP generated. Your OTP is {otp}. Enter it to continue."})

@app.route("/verify-otp", methods=["POST"])
def verify_otp():
    data = request.json
    username, otp = data.get("username"), data.get("otp")
    stored = OTP_STORE.get(username)

    if not stored or otp != stored:
        return jsonify({"error": "Invalid OTP"}), 401

    del OTP_STORE[username]
    role = USERS[username]["role"]
    token = create_token(username, role)
    return jsonify({"access_token": token, "msg": "Login successful!", "role": role})

@app.route("/profile")
@auth_required
def profile():
    return jsonify({
        "username": request.user["sub"],
        "role": request.user["role"],
        "welcome_msg": f"Welcome, {request.user['sub']}!"
    })

@app.route("/admin")
@auth_required
@role_required("admin")
def admin_area():
    return jsonify({
        "msg": "Welcome, admin! Here are admin-specific resources.",
        "admin_data": ["User stats", "System logs", "Manage users"]
    })

@app.route("/admin/users")
@auth_required
@role_required("admin")
def admin_users():
    users_list = [{"username": u, "role": info["role"]} for u, info in USERS.items()]
    return jsonify({"users": users_list})

if __name__ == "__main__":
    app.run(port=5000, debug=True)
