from fastapi import FastAPI, Depends, HTTPException, status, Form
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, text
from sqlalchemy.orm import sessionmaker, Session, declarative_base
from datetime import datetime, timedelta
from typing import Optional, List
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
from jose import JWTError, jwt
import os
from dotenv import load_dotenv
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import re
import bcrypt

# Load environment variables
load_dotenv()

# Create FastAPI app
app = FastAPI()

# Health check endpoint
@app.get("/health")
async def health_check():
    return {"status": "healthy"}

# Simple CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods
    allow_headers=["*"],  # Allows all headers
)

# Database configuration
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise ValueError("DATABASE_URL environment variable is not set")

# Ensure the database URL starts with postgresql://
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# JWT configuration
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-here")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Password hashing with explicit bcrypt configuration
pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
    bcrypt__rounds=12,
    bcrypt__ident="2b"
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="Login")

# Database models
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    user_name = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    mobile = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    otp = Column(String, nullable=True)
    otp_expires = Column(DateTime, nullable=True)

# Initialize database
def init_db():
    try:
        # Create all tables
        Base.metadata.create_all(bind=engine)
        
        # Create initial users
        db = SessionLocal()
        try:
            # Check if admin user already exists
            admin = db.query(User).filter(User.email == "admin@example.com").first()
            if not admin:
                # Create admin user
                admin = User(
                    user_name="admin",
                    email="admin@example.com",
                    mobile="1234567890",
                    hashed_password=pwd_context.hash("admin123"),
                    is_admin=True
                )
                db.add(admin)
                db.commit()
                print("Admin user created successfully")
            else:
                print("Admin user already exists")
        except Exception as e:
            print(f"Error creating admin user: {e}")
            db.rollback()
        finally:
            db.close()
    except Exception as e:
        print(f"Error initializing database: {e}")

# Initialize database
init_db()

# Database dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.get("/")
def read_root():
    return {"message": "Welcome to FastAPI Auth API"}

# Validation functions
def validate_email(email: str) -> bool:
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(email_regex, email))

def validate_mobile(mobile: str) -> bool:
    mobile_regex = r'^[0-9]{10}$'
    return bool(re.match(mobile_regex, mobile))

def validate_password(password: str) -> bool:
    # Password should be at least 8 characters long and contain at least one number and one special character
    password_regex = r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$'
    return bool(re.match(password_regex, password))

@app.post("/Register")
async def register_user(
    user_name: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    mobile: str = Form(...),
    db: Session = Depends(get_db)
):
    try:
        # Validate input fields
        if not validate_email(email):
            return JSONResponse(
                status_code=400,
                content={"detail": "Invalid email format"}
            )
        
        if not validate_mobile(mobile):
            return JSONResponse(
                status_code=400,
                content={"detail": "Invalid mobile number format. Must be 10 digits"}
            )
        
        if not validate_password(password):
            return JSONResponse(
                status_code=400,
                content={"detail": "Password must be at least 8 characters long and contain at least one number and one special character"}
            )
        
        if len(user_name) < 3:
            return JSONResponse(
                status_code=400,
                content={"detail": "Username must be at least 3 characters long"}
            )
        
        # Check for existing email
        existing_email = db.query(User).filter(User.email == email).first()
        if existing_email:
            return JSONResponse(
                status_code=400,
                content={"detail": "Email already registered"}
            )
        
        # Check for existing username
        existing_username = db.query(User).filter(User.user_name == user_name).first()
        if existing_username:
            return JSONResponse(
                status_code=400,
                content={"detail": "Username already taken"}
            )
        
        # Check for existing mobile
        existing_mobile = db.query(User).filter(User.mobile == mobile).first()
        if existing_mobile:
            return JSONResponse(
                status_code=400,
                content={"detail": "Mobile number already registered"}
            )
        
        hashed_password = pwd_context.hash(password)
        db_user = User(
            user_name=user_name,
            email=email,
            mobile=mobile,
            hashed_password=hashed_password
        )
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
        
        return JSONResponse(
            status_code=201,
            content={"message": "User registered successfully", "user_id": db_user.id}
        )
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"detail": "Server error occurred during registration"}
        )

@app.post("/Login")
async def login(
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    try:
        if not email or not password:
            return JSONResponse(
                status_code=400,
                content={"detail": "Email and password are required"}
            )
        
        if not validate_email(email):
            return JSONResponse(
                status_code=400,
                content={"detail": "Invalid email format"}
            )
        
        user = db.query(User).filter(User.email == email).first()
        if not user:
            return JSONResponse(
                status_code=401,
                content={"detail": "Email not registered"}
            )
        
        if not user.is_active:
            return JSONResponse(
                status_code=401,
                content={"detail": "Account is deactivated"}
            )
        
        if not pwd_context.verify(password, user.hashed_password):
            return JSONResponse(
                status_code=401,
                content={"detail": "Incorrect password"}
            )
        
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user.email}, expires_delta=access_token_expires
        )
        
        return JSONResponse(
            status_code=200,
            content={
                "access_token": access_token,
                "token_type": "bearer",
                "user_id": user.id,
                "user_name": user.user_name,
                "email": user.email,
                "mobile": user.mobile
            }
        )
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"detail": "Server error occurred during login"}
        )

@app.post("/forgot-password")
async def forgot_password(mobile: str = Form(...), db: Session = Depends(get_db)):
    try:
        if not mobile:
            return JSONResponse(
                status_code=400,
                content={"detail": "Mobile number is required"}
            )
        
        if not validate_mobile(mobile):
            return JSONResponse(
                status_code=400,
                content={"detail": "Invalid mobile number format. Must be 10 digits"}
            )
        
        user = db.query(User).filter(User.mobile == mobile).first()
        if not user:
            return JSONResponse(
                status_code=404,
                content={"detail": "Mobile number not registered"}
            )
        
        if not user.is_active:
            return JSONResponse(
                status_code=401,
                content={"detail": "Account is deactivated"}
            )
        
        otp = "9999"  # For testing purposes
        user.otp = otp
        user.otp_expires = datetime.utcnow() + timedelta(minutes=10)
        db.commit()
        
        return JSONResponse(
            status_code=200,
            content={"message": "OTP sent to your mobile", "otp": otp}
        )
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"detail": "Server error occurred while processing forgot password request"}
        )

@app.post("/verify-otp")
async def verify_otp(
    mobile: str = Form(...),
    otp: str = Form(...),
    db: Session = Depends(get_db)
):
    try:
        if not mobile or not otp:
            return JSONResponse(
                status_code=400,
                content={"detail": "Mobile number and OTP are required"}
            )
        
        if not validate_mobile(mobile):
            return JSONResponse(
                status_code=400,
                content={"detail": "Invalid mobile number format. Must be 10 digits"}
            )
        
        user = db.query(User).filter(User.mobile == mobile).first()
        if not user:
            return JSONResponse(
                status_code=404,
                content={"detail": "Mobile number not registered"}
            )
        
        if not user.otp:
            return JSONResponse(
                status_code=400,
                content={"detail": "No OTP requested for this mobile number"}
            )
        
        if datetime.utcnow() > user.otp_expires:
            return JSONResponse(
                status_code=400,
                content={"detail": "OTP has expired"}
            )
        
        if user.otp != otp:
            return JSONResponse(
                status_code=400,
                content={"detail": "Invalid OTP"}
            )
        
        user.otp = None
        user.otp_expires = None
        db.commit()
        
        return JSONResponse(
            status_code=200,
            content={"message": "OTP verified successfully", "user_id": user.id}
        )
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"detail": "Server error occurred while verifying OTP"}
        )

@app.post("/update-password")
async def update_password(
    id: int = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    try:
        if not id or not password:
            return JSONResponse(
                status_code=400,
                content={"detail": "User ID and new password are required"}
            )
        
        if not validate_password(password):
            return JSONResponse(
                status_code=400,
                content={"detail": "Password must be at least 8 characters long and contain at least one number and one special character"}
            )
        
        user = db.query(User).filter(User.id == id).first()
        if not user:
            return JSONResponse(
                status_code=404,
                content={"detail": "User not found"}
            )
        
        if not user.is_active:
            return JSONResponse(
                status_code=401,
                content={"detail": "Account is deactivated"}
            )
        
        user.hashed_password = pwd_context.hash(password)
        db.commit()
        
        return JSONResponse(
            status_code=200,
            content={"message": "Password updated successfully"}
        )
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"detail": "Server error occurred while updating password"}
        )

@app.get("/users")
def get_all_users(db: Session = Depends(get_db)):
    users = db.query(User).all()
    user_list = []
    for user in users:
        user_list.append({
            "id": user.id,
            "email": user.email,
            "full_name": user.user_name,
            "is_active": user.is_active,
            "created_at": user.created_at.isoformat()
        })
    return {"users": user_list}

# Helper functions
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt 
