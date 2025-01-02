import os
from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from dotenv import load_dotenv
from flask_cors import CORS  # לשימוש ב-CORS

# טעינת משתני סביבה מקובץ .env
load_dotenv()

app = Flask(__name__)

# מפתח סודי ליצירת JWT (נטען מקובץ .env)
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
jwt = JWTManager(app)

# הפעלת CORS כדי לאפשר תקשורת בין Frontend ל-Backend
CORS(app)

@app.route("/")
def home():
    return "Welcome to the Flask App!"

# נתיב ל-Login (יוצר JWT)
@app.route('/login', methods=['POST'])
def login():
    # קריאה של שם משתמש וסיסמה מקובץ .env
    admin_username = os.getenv('ADMIN_USERNAME')
    admin_password = os.getenv('ADMIN_PASSWORD')

    # קבלת שם משתמש וסיסמה מהבקשה
    username = request.json.get("username", None)
    password = request.json.get("password", None)

    # בדיקה אם שם המשתמש והסיסמה נכונים
    if username == admin_username and password == admin_password:
        access_token = create_access_token(identity={"username": username})
        return jsonify(access_token=access_token), 200
    else:
        return jsonify({"msg": "Invalid credentials"}), 401

# נתיב חישוב מספר (מוגן עם JWT)
@app.route('/calculate', methods=['POST'])
@jwt_required()
def calculate():
    current_user = get_jwt_identity()  # מזהה את המשתמש המחובר
    
    # קבלת מספר מה-Frontend
    number = request.json.get("number", None)
    
    if number is None or not isinstance(number, (int, float)):
        return jsonify({"msg": "Invalid number"}), 400
    
    # חישוב (לדוגמה: הכפלה ב-2)
    result = number * 2
    
    return jsonify({
        "username": current_user["username"],  # מחזיר את שם המשתמש
        "original_number": number,            # המספר המקורי
        "calculated_result": result           # התוצאה של החישוב
    }), 200

if __name__ == "__main__":
    app.run(port=5000)