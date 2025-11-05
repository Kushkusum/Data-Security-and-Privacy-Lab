from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
import base64

app = Flask(__name__)

# -------------------------
# Global storage for demo
# -------------------------
PRIVATE_KEY = None
PUBLIC_KEY = None

# -------------------------
# Generate RSA keys
# -------------------------
@app.route("/generate-keys", methods=["GET"])
def generate_keys():
    global PRIVATE_KEY, PUBLIC_KEY
    PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    PUBLIC_KEY = PRIVATE_KEY.public_key()

    pem_private = PRIVATE_KEY.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()

    pem_public = PUBLIC_KEY.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    return jsonify({"private_key": pem_private, "public_key": pem_public})

# -------------------------
# Sign a message
# -------------------------
@app.route("/sign", methods=["POST"])
def sign_message():
    global PRIVATE_KEY
    data = request.json
    message = data.get("message")
    if not PRIVATE_KEY:
        return jsonify({"error": "Keys not generated yet!"}), 400
    if not message:
        return jsonify({"error": "Message is required!"}), 400

    signature = PRIVATE_KEY.sign(
        message.encode(),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

    signature_b64 = base64.b64encode(signature).decode()
    return jsonify({"signature": signature_b64})

# -------------------------
# Verify a signature
# -------------------------
@app.route("/verify", methods=["POST"])
def verify_signature():
    global PUBLIC_KEY
    data = request.json
    message = data.get("message")
    signature_b64 = data.get("signature")

    if not PUBLIC_KEY:
        return jsonify({"error": "Keys not generated yet!"}), 400
    if not message or not signature_b64:
        return jsonify({"error": "Message and signature required!"}), 400

    signature = base64.b64decode(signature_b64)

    try:
        PUBLIC_KEY.verify(
            signature,
            message.encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return jsonify({"valid": True, "msg": "Signature is valid!"})
    except Exception as e:
        return jsonify({"valid": False, "msg": "Invalid signature!"})

# -------------------------
# Serve UI
# -------------------------
app = Flask(__name__, static_url_path='', static_folder='static')

@app.route("/")
def index():
    return app.send_static_file("index.html")


if __name__ == "__main__":
    app.run(port=5000, debug=True)
