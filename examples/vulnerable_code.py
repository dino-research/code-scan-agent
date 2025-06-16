"""
Ví dụ code Python có lỗ hổng bảo mật để test agent
"""
import sqlite3
import subprocess
import os

# 1. SQL Injection vulnerability
def get_user_by_id(user_id):
    """Lỗ hổng SQL Injection"""
    conn = sqlite3.connect('users.db')
    # Vulnerable: String formatting trực tiếp
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return conn.execute(query).fetchone()

def login_user(username, password):
    """Lỗ hổng SQL Injection khác"""
    conn = sqlite3.connect('users.db')
    # Vulnerable: String concatenation
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    return conn.execute(query).fetchone()

# 2. Command Injection vulnerability
def run_system_command(user_input):
    """Lỗ hổng Command Injection"""
    # Vulnerable: Chạy command với user input
    command = f"ls -la {user_input}"
    return subprocess.run(command, shell=True, capture_output=True)

def backup_file(filename):
    """Lỗ hổng Command Injection khác"""
    # Vulnerable: os.system với user input
    os.system(f"cp {filename} /backup/")

# 3. Hardcoded credentials
DATABASE_PASSWORD = "admin123"  # Hardcoded password
API_KEY = "sk-1234567890abcdef"  # Hardcoded API key
SECRET_TOKEN = "secret_token_value"  # Hardcoded secret

# 4. Weak cryptography
import hashlib

def weak_hash(password):
    """Sử dụng MD5 - thuật toán yếu"""
    return hashlib.md5(password.encode()).hexdigest()

# 5. Path traversal vulnerability
def read_file(filename):
    """Lỗ hổng Path Traversal"""
    # Vulnerable: Không validate path
    with open(f"/uploads/{filename}", 'r') as f:
        return f.read()

# 6. Information disclosure
def debug_info(request):
    """Lộ thông tin debug"""
    # Vulnerable: Lộ thông tin hệ thống
    return {
        "debug": True,
        "system_info": os.uname(),
        "env_vars": dict(os.environ),
        "request_data": request
    }

# 7. Insecure randomness
import random

def generate_session_id():
    """Tạo session ID không an toàn"""
    # Vulnerable: Sử dụng random thay vì secrets
    return str(random.randint(100000, 999999))

# 8. XXE vulnerability potential
import xml.etree.ElementTree as ET

def parse_xml(xml_data):
    """Có thể có lỗ hổng XXE"""
    # Potentially vulnerable: XML parsing without disabling external entities
    root = ET.fromstring(xml_data)
    return root

# 9. Eval injection
def calculate(expression):
    """Lỗ hổng Code Injection"""
    # Vulnerable: Sử dụng eval với user input
    result = eval(expression)
    return result

# 10. Unsafe deserialization
import pickle

def load_user_data(data):
    """Lỗ hổng Unsafe Deserialization"""
    # Vulnerable: Pickle deserialization
    return pickle.loads(data) 