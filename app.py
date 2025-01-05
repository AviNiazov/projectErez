import os
import jwt  
from datetime import datetime, timedelta
from flask import Flask, jsonify, request
from dotenv import load_dotenv
from flask_cors import CORS

load_dotenv()
# aviniazov7
app = Flask(__name__)

app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
CORS(app)

def create_access_token(identity):
    try:
        print("Creating access token for:", identity)  # Debugging
        payload = {
            "identity": identity,
            "exp": datetime.utcnow() + timedelta(hours=1)
        }
        token = jwt.encode(payload, app.config['JWT_SECRET_KEY'], algorithm="HS256")
        print("Access token created successfully")  # Debugging
        return token
    except Exception as e:
        print("Error while creating token:", e)  # Debugging
        raise e

def decode_access_token(token):
    try:
        print("Decoding token:", token)  # Debugging
        payload = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=["HS256"])
        print("Token decoded successfully:", payload)  # Debugging
        return payload
    except jwt.ExpiredSignatureError:
        print("Token has expired")  # Debugging
        return {"msg": "Token has expired"}
    except jwt.InvalidTokenError as e:
        print("Invalid token error:", e)  # Debugging
        return {"msg": "Invalid token"}

@app.route("/") # home page
def home():
    print("Home route accessed")  # Debugging
    return "Welcome to the Flask App!"

@app.route('/login', methods=['POST'])
def login():
    print("Login route accessed")  # Debugging
    admin_username = os.getenv('ADMIN_USERNAME')
    admin_password = os.getenv('ADMIN_PASSWORD')

    body = request.get_json()
    print("Login request body:", body)  # Debugging

    if not body:
        print("Request body is missing")  # Debugging
        return jsonify({"msg": "Request body is missing"}), 400

    username = body.get("username", None)
    password = body.get("password", None)

    if username == admin_username and password == admin_password:
        try:
            access_token = create_access_token(identity={"username": username})
            print("Login successful for user:", username)  # Debugging
            return jsonify(access_token=access_token), 200
        except Exception as e:
            print("Error during login token creation:", e)  # Debugging
            return jsonify({"msg": "Error creating token"}), 500
    else:
        print("Invalid credentials for user:", username)  # Debugging
        return jsonify({"msg": "Invalid credentials"}), 401

@app.route('/calculate', methods=['POST'])
def calculate():
    print("Calculate route accessed")  # Debugging
    auth_header = request.headers.get('Authorization', None)

    if not auth_header or not auth_header.startswith("Bearer "):
        print("Missing or invalid Authorization header")  # Debugging
        return jsonify({"msg": "Missing or invalid Authorization header"}), 401

    token = auth_header.split(" ")[1]
    decoded_token = decode_access_token(token)

    if "msg" in decoded_token:
        print("Token error:", decoded_token["msg"])  # Debugging
        return jsonify(decoded_token), 401

    current_user = decoded_token["identity"]

    body = request.get_json()
    print("Calculate request body:", body)  # Debugging

    if not body:
        print("Request body is missing")  # Debugging
        return jsonify({"msg": "Request body is missing"}), 400

    number = body.get("number", None)

    if number is None or not isinstance(number, (int, float)):
        print("Invalid number received:", number)  # Debugging
        return jsonify({"msg": "Invalid number"}), 400

    result = number * 2
    print("Calculation successful:", {"original_number": number, "result": result})  # Debugging

    return jsonify({
        "username": current_user["username"],
        "original_number": number,
        "calculated_result": result
    }), 200

if __name__ == "__main__":
    print("Starting the Flask app...")  # Debugging
    app.run(host="0.0.0.0", port=5000, ssl_context=("cert.pem", "key.pem"))