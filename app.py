import os
from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from dotenv import load_dotenv
from flask_cors import CORS 

load_dotenv()

app = Flask(__name__)

app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
jwt = JWTManager(app)

CORS(app)

@app.route("/")
def home():
    return "Welcome to the Flask App!"

@app.route('/login', methods=['POST'])
def login():
    admin_username = os.getenv('ADMIN_USERNAME')
    admin_password = os.getenv('ADMIN_PASSWORD')

    username = request.json.get("username", None)
    password = request.json.get("password", None)

    if username == admin_username and password == admin_password:
        access_token = create_access_token(identity={"username": username})
        return jsonify(access_token=access_token), 200
    else:
        return jsonify({"msg": "Invalid credentials"}), 401

@app.route('/calculate', methods=['POST'])
@jwt_required()
def calculate():
    current_user = get_jwt_identity() 
    
    number = request.json.get("number", None)
    
    if number is None or not isinstance(number, (int, float)):
        return jsonify({"msg": "Invalid number"}), 400
    
    result = number * 2
    
    return jsonify({
        "username": current_user["username"],   
        "original_number": number,             
        "calculated_result": result            
    }), 200

if __name__ == "__main__":
    app.run(port=5000)
