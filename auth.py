from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
from models import UserCreate, UserLogin
from dependencies import oauth2_scheme, SECRET_KEY, ALGORITHM, get_db
from middleware import role_required
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi.responses import JSONResponse
import logging
import mysql.connector

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("app.log"),  # Log to a file
        logging.StreamHandler()  # Log to the console
    ]
)
logger = logging.getLogger(__name__)

# Define tags for grouping endpoints
tags_metadata = [
    {
        "name": "Authentication",
        "description": "Endpoints for user authentication (signup and login).",
    },
    {
        "name": "Admin",
        "description": "Endpoints accessible only to users with the 'Admin' role.",
    },
    {
        "name": "Testing",
        "description": "Endpoints for testing features like rate limiting.",
    },
]

# Initialize FastAPI with metadata
app = FastAPI(
    title="Secure Authentication API",
    description="An API for secure user authentication and authorization using JWT and role-based access control.",
    version="1.0.0",
    contact={
        "name": "Your Name",
        "email": "your.email@example.com",
    },
    license_info={
        "name": "MIT",
    },
    openapi_tags=tags_metadata,  # Add tags metadata
)

# Rate limiting setup
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Custom exception handler for rate limiting
@app.exception_handler(RateLimitExceeded)
async def rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded):
    logger.warning(f"Rate limit exceeded for {request.client.host}")
    return JSONResponse(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        content={"detail": "Rate limit exceeded. Please try again later."},
    )

# Helper functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# User signup
@app.post(
    "/signup",
    summary="Create a new user",
    description="Register a new user with an email and password.",
    response_description="User created successfully",
    tags=["Authentication"],  # Add tag
)
def signup(user: UserCreate):
    """
    Register a new user.

    - **email**: The user's email address (must be unique).
    - **password**: The user's password (will be hashed before storage).
    """
    db = get_db()
    cursor = db.cursor()
    try:
        # Check if email already exists
        cursor.execute("SELECT id FROM users WHERE email = %s", (user.email,))
        if cursor.fetchone():
            logger.warning(f"Signup failed: Email {user.email} already registered")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered",
            )

        # Get the default role ID for 'User'
        cursor.execute("SELECT id FROM roles WHERE name = 'User'")
        role_id = cursor.fetchone()[0]

        # Hash the password and insert the new user
        password_hash = get_password_hash(user.password)
        cursor.execute(
            "INSERT INTO users (email, password_hash, role_id) VALUES (%s, %s, %s)",
            (user.email, password_hash, role_id),
        )
        db.commit()
        logger.info(f"New user signed up: {user.email}")
        return {"message": "User created successfully"}
    except mysql.connector.Error as e:
        logger.error(f"Database error during signup: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error: {e}",
        )
    finally:
        cursor.close()
        db.close()

# User login
@app.post(
    "/login",
    summary="Authenticate a user",
    description="Authenticate a user with their email and password. Returns a JWT token for accessing protected routes.",
    response_description="JWT token for authentication",
    tags=["Authentication"],  # Add tag
)
def login(user: UserLogin):
    """
    Authenticate a user and return a JWT token.

    - **email**: The user's email address.
    - **password**: The user's password.
    """
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute("SELECT id, password_hash, role_id FROM users WHERE email = %s", (user.email,))
        user_data = cursor.fetchone()
        if not user_data or not verify_password(user.password, user_data[1]):
            logger.warning(f"Login failed for email: {user.email}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Incorrect email or password",
            )
        access_token = create_access_token(data={"sub": user.email, "role_id": user_data[2]})
        logger.info(f"User logged in: {user.email}")
        return {"access_token": access_token, "token_type": "bearer"}
    except mysql.connector.Error as e:
        logger.error(f"Database error during login: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error: {e}",
        )
    finally:
        cursor.close()
        db.close()

# Protected route with role-based access control
@app.get(
    "/admin",
    summary="Admin-only route",
    description="Accessible only to users with the 'Admin' role.",
    response_description="Welcome message for admins",
    tags=["Admin"],  # Add tag
)
@limiter.limit("5/minute")
async def admin_route(request: Request, token: str = Depends(oauth2_scheme)):
    """
    Access the admin-only route.

    - **token**: JWT token for authentication (provided in the Authorization header).
    """
    try:
        await role_required("Admin", token)
        logger.info(f"Admin route accessed by {request.client.host}")
        return {"message": "Welcome, Admin!"}
    except HTTPException as e:
        logger.warning(f"Unauthorized access to admin route: {e.detail}")
        raise e
    except JWTError:
        logger.warning("Invalid or expired token provided for admin route")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )

# Rate-limited route
@app.get(
    "/limited",
    summary="Rate-limited route",
    description="A route with a rate limit of 5 requests per minute.",
    response_description="Rate-limited response",
    tags=["Testing"],  # Add tag
)
@limiter.limit("5/minute")
async def limited_route(request: Request):
    """
    Access a rate-limited route.

    - **request**: The incoming HTTP request.
    """
    logger.info(f"Rate-limited route accessed by {request.client.host}")
    return {"message": "This is a rate-limited route"}