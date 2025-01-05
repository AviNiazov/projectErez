import os
import jwt  
from datetime import datetime, timedelta
from flask import Flask, jsonify, request
from dotenv import load_dotenv
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv()

app = Flask(__name__)

app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///app.db')  # כברירת מחדל SQLite
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)   
CORS(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

    def __init__(self, username, password):
        self.username = username
        self.password = generate_password_hash(password)   

    def check_password(self, password):
        return check_password_hash(self.password, password)

def create_access_token(identity):
    try:
        payload = {
            "identity": identity,
            "exp": datetime.utcnow() + timedelta(hours=1)
        }
        token = jwt.encode(payload, app.config['JWT_SECRET_KEY'], algorithm="HS256")
        return token
    except Exception as e:
        raise e

def decode_access_token(token):
    try:
        payload = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        return {"msg": "Token has expired"}
    except jwt.InvalidTokenError:
        return {"msg": "Invalid token"}

@app.route("/")
def home():
    return "Welcome to the Flask App with Database!"

@app.route('/register', methods=['POST'])
def register():
    body = request.get_json()
    if not body:
        return jsonify({"msg": "Request body is missing"}), 400

    username = body.get("username")
    password = body.get("password")

    if not username or not password:
        return jsonify({"msg": "Username and password are required"}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({"msg": "Username already exists"}), 400

    new_user = User(username=username, password=password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"msg": "User registered successfully"}), 201

@app.route('/login', methods=['POST'])
def login():
    body = request.get_json()
    if not body:
        return jsonify({"msg": "Request body is missing"}), 400

    username = body.get("username")
    password = body.get("password")

    user = User.query.filter_by(username=username).first()

    if not user or not user.check_password(password):
        return jsonify({"msg": "Invalid credentials"}), 401

    access_token = create_access_token(identity={"username": username})
    return jsonify(access_token=access_token), 200

@app.route('/calculate', methods=['POST'])
def calculate():
    auth_header = request.headers.get('Authorization', None)
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"msg": "Missing or invalid Authorization header"}), 401

    token = auth_header.split(" ")[1]
    decoded_token = decode_access_token(token)

    if "msg" in decoded_token:
        return jsonify(decoded_token), 401

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
    db.create_all()  
    app.run(port=5000)