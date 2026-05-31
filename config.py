import os
from datetime import timedelta
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Config:
    # Flask application secret key
    SECRET_KEY = os.environ.get('SECRET_KEY', 'default_threat_intel_secret_key_1337!')
    
    # AES Cryptography Secret Key for storing encrypted API keys in the DB (must be 32 bytes URL-safe base64 encoded)
    AES_SECRET_KEY = os.environ.get('AES_SECRET_KEY', '7J_Yj2Q-6aGjT4wX-sU1ZkU9XhC-y6_F2v5O6X7z9zU=')
    
    # Database Configuration
    DB_USER = os.environ.get('DB_USER')
    DB_PASSWORD = os.environ.get('DB_PASSWORD')
    DB_HOST = os.environ.get('DB_HOST', 'localhost')
    DB_PORT = os.environ.get('DB_PORT', '3306')
    DB_NAME = os.environ.get('DB_NAME')
    
    if DB_USER and DB_PASSWORD and DB_NAME:
        # MySQL Connection String using PyMySQL driver
        SQLALCHEMY_DATABASE_URI = f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
    else:
        # Fallback to local SQLite for dev environments where MySQL is not yet configured
        BASE_DIR = os.path.abspath(os.path.dirname(__file__))
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{os.path.join(BASE_DIR, 'threat_intel.db')}"
        print("[Config] WARNING: DB credentials missing in .env. Falling back to local SQLite database.")
        
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Session Cookie Security Configuration
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'False').lower() in ('true', '1')
    SESSION_COOKIE_SAMESITE = 'Strict'
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)
    
    # Rate Limiting & Admin parameters
    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_TIME_MINUTES = 15
