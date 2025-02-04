from fastapi.security import OAuth2PasswordBearer
import os
from dotenv import load_dotenv
import mysql.connector

load_dotenv()

# JWT configuration
SECRET_KEY = os.getenv("JWT_SECRET_KEY")
ALGORITHM = os.getenv("JWT_ALGORITHM")

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Database connection
def get_db():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="hamza",
        database="auth_system"
    )