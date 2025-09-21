from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from jose import JWTError, jwt
import os
from dotenv import load_dotenv
import datetime


from backend.database import get_db, User, create_db_tables
from backend.utils import SECRET_KEY, ALGORITHM
from backend.auth import router as auth_router
from backend.services import router as services_router

# Load environment variables
load_dotenv()

# Create database tables
create_db_tables()

app = FastAPI(
    title="Zenith Backend API",
    description="Backend for Zenith Cloud Storage Manager Extension",
    version="1.0.0"
)

# Configure CORS for frontend and extension integration
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:3000")
EXTENSION_ID = os.getenv("EXTENSION_ID", "adblmalbbgflimcdflbgfkpgonljeccd")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        FRONTEND_URL,
        f"chrome-extension://{EXTENSION_ID}",
        "http://localhost",
        "http://localhost:3000",
        "http://localhost:8000"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth_router)
app.include_router(services_router)

# OAuth2 scheme for token authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    """Dependency to get current user from JWT token"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    user = db.query(User).filter(User.user_id == user_id).first()
    if user is None:
        raise credentials_exception
    return user

@app.get("/")
def read_root():
    """Root endpoint - API information"""
    return {
        "message": "Zenith Backend API",
        "version": "1.0.0",
        "documentation": "/docs",
        "endpoints": {
            "auth": {
                "register": "/auth/register",
                "login": "/auth/login",
                "google_login": "/auth/google/login",
                "dropbox_login": "/auth/dropbox/login"
            },
            "services": {
                "upload_url": "/services/upload-url",
                "download_url": "/services/download-url",
                "storage_info": "/services/storage/{service}"
            }
        }
    }

@app.get("/health")
def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}

@app.get("/user/services")
def get_user_services(current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    """Get all connected cloud services for the current user"""
    from backend.database import UserCloudService
    services = db.query(UserCloudService).filter(
        UserCloudService.user_id == current_user.user_id,
        UserCloudService.is_active == True
    ).all()
    
    return {
        "user_id": current_user.user_id,
        "email": current_user.email,
        "services": [
            {
                "id": str(service.id),
                "service_name": service.service_name,
                "total_space": service.total_space,
                "used_space": service.used_space,
                "available_space": service.total_space - service.used_space,
                "is_active": service.is_active
            }
            for service in services
        ]
    }

@app.get("/user/profile")
def get_user_profile(current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    """Get current user profile"""
    return {
        "user_id": current_user.user_id,
        "email": current_user.email,
        "created_at": current_user.created_at
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)