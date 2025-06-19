# app.py (เวอร์ชันทดสอบสุดท้าย: ข้ามการตรวจสอบรหัสผ่าน)
import os
import json
from datetime import timedelta
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_jwt_extended import create_access_token, JWTManager

# --- การตั้งค่าพื้นฐาน ---
app = Flask(__name__)
CORS(app) 

# --- การตั้งค่าความปลอดภัย ---
app.config["JWT_SECRET_KEY"] = os.environ.get('JWT_SECRET_KEY', 'a-strong-default-secret-key-for-dev')
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=8)
jwt = JWTManager(app)

# --- ========================================================== ---
# ---  ข้อมูลผู้ใช้ชั่วคราวสำหรับ Debug ---
# --- ========================================================== ---
DEBUG_USERS = {
  "admin001": {
    "role": "admin",
    "full_name": "แอดมิน 001 (Debug Mode)"
  }
}
# --- ========================================================== ---

# --- Login Endpoint (ข้ามการตรวจสอบรหัสผ่าน) ---
@app.route('/api/login', methods=['POST'])
def login():
    try:
        username = request.json.get("username", None)
        print(f"--- Login Bypass attempt for: '{username}' ---")

        # ตรวจสอบแค่ว่า username คือ admin001 หรือไม่
        if username == "admin001":
            print(f"Username '{username}' matches. Bypassing password check. SUCCESS.")
            user_data = DEBUG_USERS.get(username)
            additional_claims = {"role": user_data["role"], "full_name": user_data["full_name"]}
            access_token = create_access_token(identity=username, additional_claims=additional_claims)
            return jsonify(access_token=access_token)
        else:
            print(f"Login failed: User '{username}' is not the debug user.")
            return jsonify({"msg": "ชื่อผู้ใช้ไม่ถูกต้อง"}), 401
            
    except Exception as e:
        print(f"[ERROR] An unexpected error occurred: {e}")
        return jsonify({"msg": "เกิดข้อผิดพลาดภายในเซิร์ฟเวอร์"}), 500
        
# --- API อื่นๆ จะถูกปิดใช้งานชั่วคราว ---
@app.route('/api/register', methods=['POST'])
def register():
    return jsonify({"msg": "Registration is temporarily disabled."}), 403

@app.route('/api/admin/<path:path>', methods=['GET', 'POST'])
def admin_routes(path):
    return jsonify({"msg": "Admin routes are temporarily disabled."}), 403

@app.route('/api/files', methods=['GET'])
def files_route():
     return jsonify([{"id": "test001", "name": "Debug Mode Active.pdf", "category": "งาน IT", "size": "1 MB", "modified_date": "2025-01-01T12:00:00Z", "uploader": "System", "filename": ""}])

# --- Main Execution ---
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=False)
