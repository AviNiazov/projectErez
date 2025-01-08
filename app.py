#8/1/25
import os
from datetime import datetime, timedelta
from flask import Flask, jsonify, request
from dotenv import load_dotenv
from flask_cors import CORS
import jwt
from functools import wraps   

load_dotenv()
# aviniazov7
app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')

CORS(app, supports_credentials=True)

def create_access_token(identity):
    """Create a JWT access token."""
    try:
        payload = {
            "identity": identity,
            "exp": datetime.utcnow() + timedelta(hours=1)
        }
        return jwt.encode(payload, app.config['JWT_SECRET_KEY'], algorithm="HS256")
    except Exception as e:
        app.logger.error(f"Error while creating token: {e}")
        raise

def decode_access_token(token):
    """Decode a JWT access token."""
    try:
        payload = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        return {"msg": "Token has expired"}
    except jwt.InvalidTokenError:
        return {"msg": "Invalid token"}

def jwt_required(func):
    """Decorator to ensure a valid JWT is provided."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get('Authorization', None)
        if not auth_header or not auth_header.startswith("Bearer "):
            app.logger.warning("Missing or invalid Authorization header")
            return jsonify({"msg": "Missing or invalid Authorization header"}), 401

        token = auth_header.split(" ")[1]
        decoded_token = decode_access_token(token)

        if "msg" in decoded_token:
            app.logger.error(f"Token error: {decoded_token['msg']}")
            return jsonify(decoded_token), 401

        return func(decoded_token, *args, **kwargs)
    return wrapper

@app.route("/")
@jwt_required
def home(decoded_token):
    """Home route."""
    app.logger.info(f"Home route accessed by {decoded_token['identity']['username']}")
    return "Welcome to the Flask App!"

@app.route('/login', methods=['POST'])
def login():
    """Login route for authentication."""
    admin_username = os.getenv('ADMIN_USERNAME')
    admin_password = os.getenv('ADMIN_PASSWORD')

    app.logger.info(f"ADMIN_USERNAME: {admin_username}")
    app.logger.info(f"ADMIN_PASSWORD: {admin_password}")

    body = request.get_json()
    if not body:
        app.logger.error("Request body is missing")
        return jsonify({"msg": "Request body is missing"}), 400

    username = body.get("username")
    password = body.get("password")
    app.logger.info(f"Received username: {username}")
    app.logger.info(f"Received password: {password}")

    if username == admin_username and password == admin_password:
        try:
            access_token = create_access_token(identity={"username": username})
            app.logger.info(f"Login successful for user: {username}")
            return jsonify(access_token=access_token), 200
        except Exception as e:
            app.logger.error(f"Error during login token creation: {e}")
            return jsonify({"msg": "Error creating token"}), 500
    else:
        app.logger.warning(f"Invalid credentials for user: {username}")
        return jsonify({"msg": "Invalid credentials"}), 401

@app.route('/calculate', methods=['POST'])
@jwt_required
def calculate(decoded_token):
    app.logger.info(f"Authorization Header: {request.headers.get('Authorization')}")

    current_user = decoded_token["identity"]
    body = request.get_json()

    if not body:
        return jsonify({"msg": "Request body is missing"}), 400

    number = body.get("number")

    if number is None or not isinstance(number, (int, float)):
        return jsonify({"msg": "Invalid number"}), 400

    result = number * 2
    return jsonify({
        "username": current_user["username"],
        "original_number": number,
        "calculated_result": result
    }), 200

if __name__ == "__main__":
    print("Starting the Flask app...")  # Debugging
    app.run(port=5000)