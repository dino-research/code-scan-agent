#!/usr/bin/env python3
"""
Test file chứa các secrets để test tính năng secrets detection
"""

# API Keys - Should be detected
OPENAI_API_KEY = "sk-1234567890abcdef1234567890abcdef"
GOOGLE_API_KEY = "AIzaSyABC123def456GHI789jkl012MNO345pqr"
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Database credentials - Should be detected  
DATABASE_URL = "postgresql://user:password123@localhost:5432/mydb"
MYSQL_CONNECTION = "mysql://admin:secretpass@db.example.com/production"
MONGODB_URI = "mongodb://dbuser:dbpass123@cluster.mongodb.net/database"

# Private keys - Should be detected
PRIVATE_KEY = """-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7...
-----END PRIVATE KEY-----"""

RSA_PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0z8F8jkf9X2n5Y7w3Q4R5T6U7I8O9P0L...
-----END RSA PRIVATE KEY-----"""

# JWT secrets - Should be detected
JWT_SECRET = "super-secret-jwt-key-dont-expose-this"
JWT_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

# Email credentials - Should be detected
SMTP_PASSWORD = "email_password_123"
EMAIL_API_KEY = "key-1234567890abcdef1234567890abcdef"

# Social media API keys - Should be detected
TWITTER_API_KEY = "abc123def456ghi789jkl012mno345pqr"
TWITTER_SECRET = "xyz987wvu654tsr321qpo210nml109kji"
FACEBOOK_APP_SECRET = "fb_secret_1234567890abcdef1234567890"

# Cloud service tokens - Should be detected
AZURE_CLIENT_SECRET = "azure_secret_value_12345"
GCP_SERVICE_ACCOUNT = {
    "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADA...\n-----END PRIVATE KEY-----\n",
    "client_email": "service@project.iam.gserviceaccount.com"
}

# Slack/Discord tokens - Should be detected (obfuscated for GitHub)
SLACK_BOT_TOKEN = "xoxb-" + "1234567890-1234567890123-" + "abcdefghijklmnopqrstuvwx"
DISCORD_BOT_TOKEN = "ODcyMzE0NjkzMzI4NjcxNzQ0." + "YQzL1A." + "abcdefghijklmnopqrstuvwxyz123456"

# GitHub tokens - Should be detected (obfuscated for GitHub)
GITHUB_TOKEN = "ghp_" + "1234567890abcdef1234567890abcdef12345678"
GITHUB_PERSONAL_TOKEN = "github_pat_" + "11ABCDEFG0123456789abcdefghijklmnopqrstuvwxyz"

# Hardcoded passwords in functions
def connect_to_database():
    # Bad practice - hardcoded credentials
    password = "admin123"
    username = "root"
    host = "production-db.company.com"
    
    connection_string = f"postgresql://{username}:{password}@{host}/maindb"
    return connection_string

def authenticate_user():
    # More hardcoded secrets
    api_secret = "my-super-secret-api-key-2023"
    encryption_key = "aes256-encryption-key-do-not-share"
    
    return {
        "api_secret": api_secret,
        "encryption_key": encryption_key
    }

# Certificate and key data
SSL_CERTIFICATE = """-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAKoK/heBjcOuMA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNV...
-----END CERTIFICATE-----"""

# Configuration with secrets
CONFIG = {
    "database": {
        "host": "db.example.com",
        "username": "dbadmin", 
        "password": "db_password_2023",  # Should be detected
        "port": 5432
    },
    "redis": {
        "host": "redis.example.com",
        "password": "redis_secret_key",  # Should be detected
        "port": 6379
    },
    "api_keys": {
        "stripe": "sk_live_" + "abcdef1234567890",  # Should be detected
        "paypal": "paypal_client_secret_" + "xyz",  # Should be detected
        "twilio": "twilio_auth_token_" + "123"      # Should be detected
    }
}

if __name__ == "__main__":
    print("This file contains intentional secrets for testing")
    print("DO NOT use these in production!") 