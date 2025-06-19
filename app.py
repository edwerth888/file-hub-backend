# app.py (เวอร์ชันทดสอบ: ใส่ข้อมูลผู้ใช้โดยตรงเพื่อ Debug)
import os
import json
from datetime import timedelta
from functools import wraps
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_jwt_extended import create_access_token, jwt_required, JWTManager, get_jwt
from werkzeug.security import check_password_hash

# --- การตั้งค่าพื้นฐาน ---
app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}}) 

# --- การตั้งค่าความปลอดภัย ---
app.config["JWT_SECRET_KEY"] = os.environ.get('JWT_SECRET_KEY', 'a-strong-default-secret-key-for-dev')
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=8)
jwt = JWTManager(app)

# --- ========================================================== ---
# ---  ข้อมูลผู้ใช้ชั่วคราวสำหรับ Debug (Hardcoded) ---
# --- ========================================================== ---
HARDCODED_USERS = {
  "approved_users": {
    "admin": {
      "password_hash": "pbkdf2:sha256:600000$hG3yL9bQv8zKxN4a$20a6c2e42f6e9b4d4b1a2d5e9f8c7b6a1d3f5e8c7a6b5c4d3e2f1a0b9c8d7e6f",
      "role": "admin",
      "full_name": "ผู้ดูแลระบบ"
    },
    "admin001": {
      "password_hash": "pbkdf2:sha256:600000$A0uF7bK2gL9hY3zV$9e3a6c8b2d1f0a5e7c4d3e2f1a0b9c8d7e6f1a5b9c8d7e6f1a5b9c8d7e6f1a5b",
      "role": "admin",
      "full_name": "แอดมิน 001"
    }
  }
}
# --- ========================================================== ---

# --- Login Endpoint (ใช้ข้อมูล Hardcoded) ---
@app.route('/api/login', methods=['POST'])
def login():
    try:
        username = request.json.get("username", None)
        password = request.json.get("password", None)
        print(f"--- Hardcoded Login attempt for: '{username}' ---")

        # ใช้ข้อมูลจาก HARDCODED_USERS แทนการอ่านไฟล์
        user_data = HARDCODED_USERS.get("approved_users", {}).get(username, None)
        
        if not user_data:
            print(f"Login failed: User '{username}' not in hardcoded list.")
            return jsonify({"msg": "ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง"}), 401

        print(f"Found hardcoded user '{username}'. Checking password...")
        
        # ใช้ password_hash ที่ถูกต้องจากข้อมูล Hardcoded
        if check_password_hash(user_data["password_hash"], password):
            print(f"Password for '{username}' is correct. SUCCESS.")
            additional_claims = {"role": user_data["role"], "full_name": user_data["full_name"]}
            access_token = create_access_token(identity=username, additional_claims=additional_claims)
            return jsonify(access_token=access_token)
        else:
            print(f"Login failed: Incorrect password for '{username}'.")
            return jsonify({"msg": "ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง"}), 401
    except Exception as e:
        print(f"[ERROR] An unexpected error occurred: {e}")
        return jsonify({"msg": "เกิดข้อผิดพลาดภายในเซิร์ฟเวอร์"}), 500
        
# --- API อื่นๆ จะถูกปิดใช้งานชั่วคราวเพื่อการทดสอบ Login ---
@app.route('/api/register', methods=['POST'])
def register():
    return jsonify({"msg": "Registration is temporarily disabled."}), 403

@app.route('/api/admin/<path:path>', methods=['GET', 'POST'])
def admin_routes(path):
    return jsonify({"msg": "Admin routes are temporarily disabled."}), 403

@app.route('/api/files', methods=['GET'])
def files_route():
     return jsonify([{"id": "test001", "name": "Test File.pdf", "category": "งาน IT", "size": "1 MB", "modified_date": "2025-01-01T12:00:00Z", "uploader": "System", "filename": ""}])

# --- Main Execution ---
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=False)
