# app.py (เวอร์ชันสมบูรณ์และปลอดภัย)
import os
import json
from datetime import timedelta
from functools import wraps
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_jwt_extended import create_access_token, jwt_required, JWTManager, get_jwt
from werkzeug.security import generate_password_hash, check_password_hash

# --- การตั้งค่าพื้นฐาน ---
app = Flask(__name__)
CORS(app) 

# --- การตั้งค่าความปลอดภัย ---
app.config["JWT_SECRET_KEY"] = os.environ.get('JWT_SECRET_KEY', 'a-strong-default-secret-key-for-dev')
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=8)
jwt = JWTManager(app)

# --- การจัดการฐานข้อมูลแบบไฟล์ JSON ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
USERS_FILE = os.path.join(BASE_DIR, 'users.json')
FILES_FILE = os.path.join(BASE_DIR, 'files.json')

def load_data(file_path, default_data={}):
    """ฟังก์ชันสำหรับโหลดข้อมูลจากไฟล์ JSON"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        save_data(file_path, default_data)
        return default_data

def save_data(file_path, data):
    """ฟังก์ชันสำหรับบันทึกข้อมูลลงไฟล์ JSON"""
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

# --- Decorator สำหรับตรวจสอบสิทธิ์ Admin ---
def admin_required():
    def wrapper(fn):
        @wraps(fn)
        @jwt_required()
        def decorator(*args, **kwargs):
            claims = get_jwt()
            if claims.get("role") == "admin":
                return fn(*args, **kwargs)
            else:
                return jsonify(msg="Admins only!"), 403
        return decorator
    return wrapper

# --- User & Auth Endpoints ---
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    full_name = data.get("full_name")

    if not all([username, password, full_name]):
        return jsonify({"msg": "กรุณากรอกข้อมูลให้ครบถ้วน"}), 400

    users_data = load_data(USERS_FILE, {"approved_users": {}, "pending_users": {}})
    if username in users_data.get("approved_users", {}) or username in users_data.get("pending_users", {}):
        return jsonify({"msg": "ชื่อผู้ใช้นี้มีอยู่ในระบบแล้ว"}), 409

    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
    users_data.setdefault("pending_users", {})[username] = {
        "password_hash": hashed_password,
        "role": "user",
        "full_name": full_name
    }
    save_data(USERS_FILE, users_data)
    
    return jsonify({"msg": "ลงทะเบียนสำเร็จ! กรุณารอผู้ดูแลระบบอนุมัติบัญชีของคุณ"}), 201

@app.route('/api/login', methods=['POST'])
def login():
    username = request.json.get("username", None)
    password = request.json.get("password", None)
    
    users_data = load_data(USERS_FILE)
    user_data = users_data.get("approved_users", {}).get(username, None)
    
    if user_data and check_password_hash(user_data["password_hash"], password):
        additional_claims = {"role": user_data["role"], "full_name": user_data["full_name"]}
        access_token = create_access_token(identity=username, additional_claims=additional_claims)
        return jsonify(access_token=access_token)
    
    return jsonify({"msg": "ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง หรือบัญชียังไม่ได้รับการอนุมัติ"}), 401

# --- Admin Endpoints ---
@app.route('/api/admin/all_users', methods=['GET'])
@admin_required()
def get_all_users():
    users_data = load_data(USERS_FILE)
    approved_users = users_data.get("approved_users", {})
    users_to_return = {u: {"role": d["role"], "full_name": d["full_name"]} for u, d in approved_users.items()}
    return jsonify(users_to_return)

@app.route('/api/admin/pending_users', methods=['GET'])
@admin_required()
def get_pending_users():
    users_data = load_data(USERS_FILE)
    pending_users = users_data.get("pending_users", {})
    users_to_return = {u: {"full_name": d["full_name"]} for u, d in pending_users.items()}
    return jsonify(users_to_return)

@app.route('/api/admin/approve_user', methods=['POST'])
@admin_required()
def approve_user():
    username_to_approve = request.json.get("username")
    if not username_to_approve:
        return jsonify({"msg": "Username is required"}), 400
        
    users_data = load_data(USERS_FILE)
    pending_users = users_data.get("pending_users", {})
    
    if username_to_approve in pending_users:
        user_to_move = pending_users.pop(username_to_approve)
        users_data.setdefault("approved_users", {})[username_to_approve] = user_to_move
        save_data(USERS_FILE, users_data)
        return jsonify({"msg": f"User '{username_to_approve}' has been approved."}), 200
    else:
        return jsonify({"msg": "User not found in pending list."}), 404

# --- File Endpoints ---
@app.route('/api/files', methods=['GET'])
@jwt_required()
def get_files():
    files_db = load_data(FILES_FILE, [])
    return jsonify(files_db)

# --- Main Execution ---
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=False)
