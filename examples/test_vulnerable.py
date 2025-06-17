#!/usr/bin/env python3
"""
Test file containing intentional vulnerabilities for testing file path display
"""

import subprocess
import os

def vulnerable_subprocess_call():
    """Intentionally vulnerable subprocess call for testing"""
    user_input = input("Enter command: ")
    # This is vulnerable to command injection
    subprocess.call(user_input, shell=True)  # Semgrep should detect this

def vulnerable_eval():
    """Intentionally vulnerable eval for testing"""
    user_code = input("Enter Python code: ")
    # This is dangerous - eval with user input
    result = eval(user_code)  # Semgrep should detect this
    return result

def hardcoded_credentials():
    """Intentionally hardcoded credentials for testing"""
    # These should be detected by security scanners
    password = "admin123"  # Hardcoded password
    api_key = "sk_live_abc123def456"  # Hardcoded API key
    database_url = "postgresql://user:pass@localhost/db"  # Hardcoded DB credentials
    
    return password, api_key, database_url

def sql_injection_vulnerable():
    """SQL injection vulnerability for testing"""
    import sqlite3
    
    def get_user(user_id):
        conn = sqlite3.connect('test.db')
        cursor = conn.cursor()
        
        # Vulnerable to SQL injection
        query = f"SELECT * FROM users WHERE id = {user_id}"
        cursor.execute(query)
        
        return cursor.fetchone()

if __name__ == "__main__":
    print("This file contains intentional vulnerabilities for testing")
    print("DO NOT use in production!") 