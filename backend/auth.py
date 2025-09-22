from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm  # Added OAuth2PasswordBearer
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
import requests
from urllib.parse import urlencode
import hashlib
import base64
import secrets
import json
from jose import JWTError, jwt  # Added JWTError and jwt
import time

from .database import get_db, User, UserCloudService
from sqlalchemy.orm import Session
from .schemas import UserCreate, UserOut, Token
from .utils import (
    get_password_hash, verify_password, create_access_token, 
    encrypt_token, decrypt_token, validate_token_expiry,
    SECRET_KEY, ALGORITHM  # Added SECRET_KEY and ALGORITHM
)
import os
from dotenv import load_dotenv
from pathlib import Path

load_dotenv(dotenv_path=Path(__file__).resolve().parent / '.env')

# Create the router instance
router = APIRouter(prefix="/auth", tags=["authentication"])

# OAuth2 scheme for token authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

# Helper: get current user from JWT (must be defined before using in Depends)
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

# Provider credentials (must be set in backend/.env)
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI", "http://localhost:8000/auth/google/callback")

DROPBOX_CLIENT_ID = os.getenv("DROPBOX_CLIENT_ID")
DROPBOX_CLIENT_SECRET = os.getenv("DROPBOX_CLIENT_SECRET")
DROPBOX_REDIRECT_URI = os.getenv("DROPBOX_REDIRECT_URI", "http://localhost:8000/auth/dropbox/callback")

# In-memory store for PKCE code verifiers (in production, use Redis or database)
pkce_store = {}

# In-memory store for Google Device codes (short-lived). In production use Redis/DB.
device_store = {}

def generate_pkce_codes():
    """Generate PKCE code verifier and challenge"""
    code_verifier = secrets.token_urlsafe(64)
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode()).digest()
    ).decode().replace("=", "")
    return code_verifier, code_challenge

@router.post("/register", response_model=Token)
def register_user(user_data: UserCreate, db: Session = Depends(get_db)):
    """Register a new user with email and password"""
    # Check if user already exists
    existing_user = db.query(User).filter(User.email == user_data.email).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    # Create new user with hashed password
    hashed_password = get_password_hash(user_data.password)
    new_user = User(email=user_data.email, hashed_password=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    # Create access token
    access_token = create_access_token(data={"sub": str(new_user.user_id)})
    
    return {"access_token": access_token, "token_type": "bearer"}

@router.post("/login", response_model=Token)
def login_user(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """Login user and return JWT token"""
    user = db.query(User).filter(User.email == form_data.username).first()
    
    if not user or not verify_password(form_data.password, getattr(user, 'hashed_password', '')):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token = create_access_token(data={"sub": str(user.user_id)})
    return {"access_token": access_token, "token_type": "bearer"}

@router.get("/google/login")
def google_login():
    """Redirect user to Google OAuth consent screen using PKCE"""
    if not GOOGLE_CLIENT_ID:
        raise HTTPException(status_code=500, detail="GOOGLE_CLIENT_ID not configured")
    # Generate PKCE pair and state
    code_verifier, code_challenge = generate_pkce_codes()
    state = secrets.token_urlsafe(16)
    
    auth_url = "https://accounts.google.com/o/oauth2/v2/auth"
    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope": "openid email profile https://www.googleapis.com/auth/drive https://www.googleapis.com/auth/drive.file",
        "access_type": "offline",
        "prompt": "consent",
        "include_granted_scopes": "true",
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "state": state
    }
    
    # Store the code verifier for later use
    pkce_store[state] = code_verifier
    
    return {
        "auth_url": f"{auth_url}?{urlencode(params)}",
        "state": state
    }

@router.get("/google/callback")
def google_callback(code: str, state: str, db: Session = Depends(get_db)):
    """Handle Google OAuth callback using PKCE"""
    try:
        # Retrieve the code verifier using the state parameter
        code_verifier = pkce_store.pop(state, None)
        if not code_verifier:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid state parameter"
            )
        
        # Exchange code for tokens using PKCE
        token_url = "https://oauth2.googleapis.com/token"
        if not GOOGLE_CLIENT_ID:
            raise HTTPException(status_code=500, detail="GOOGLE_CLIENT_ID not configured")
        data = {
            "client_id": GOOGLE_CLIENT_ID,
            "code": code,
            "redirect_uri": GOOGLE_REDIRECT_URI,
            "grant_type": "authorization_code",
            "code_verifier": code_verifier
        }
        if GOOGLE_CLIENT_SECRET:
            data["client_secret"] = GOOGLE_CLIENT_SECRET
        
        response = requests.post(token_url, data=data)
        token_data = response.json()
        
        if "error" in token_data:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=token_data["error_description"]
            )
        
        # Get user info from Google (try userinfo, then id_token claims)
        user_info_url = "https://www.googleapis.com/oauth2/v3/userinfo"
        headers = {"Authorization": f"Bearer {token_data['access_token']}"}
        user_info = requests.get(user_info_url, headers=headers).json()
        email = user_info.get("email")
        if not email and token_data.get("id_token"):
            try:
                claims = jwt.get_unverified_claims(token_data["id_token"])  # type: ignore
                email = claims.get("email")
            except Exception:
                email = None
        
        # Get storage quota from Google Drive
        drive_url = "https://www.googleapis.com/drive/v3/about"
        params = {"fields": "storageQuota"}
        drive_info = requests.get(drive_url, headers=headers, params=params).json()
        
        storage_quota = drive_info.get("storageQuota", {})
        total_space = int(storage_quota.get("limit", 0))
        used_space = int(storage_quota.get("usage", 0))
        
        # Find or create user in our database
        user_email = email or user_info.get("email")
        if not user_email:
            # Fallback to a pseudo-identifier if email not provided
            user_email = f"user-{secrets.token_hex(8)}@example.local"
        user = db.query(User).filter(User.email == user_email).first()
        if not user:
            # Create user without password for OAuth users
            user = User(email=user_email)
            db.add(user)
            db.commit()
            db.refresh(user)
        
        # Encrypt and store tokens
        encrypted_access = encrypt_token(token_data["access_token"])
        encrypted_refresh = encrypt_token(token_data.get("refresh_token", ""))
        token_expiry = datetime.utcnow() + timedelta(seconds=token_data["expires_in"])
        
        # Create or update cloud service connection
        cloud_service = db.query(UserCloudService).filter(
            UserCloudService.user_id == user.user_id,
            UserCloudService.service_name == "google_drive"
        ).first()
        
        if cloud_service:
            cloud_service.access_token = encrypted_access
            if token_data.get("refresh_token"):
                cloud_service.refresh_token = encrypted_refresh
            cloud_service.token_expiry = token_expiry
            cloud_service.total_space = total_space
            cloud_service.used_space = used_space
            cloud_service.is_active = True
        else:
            cloud_service = UserCloudService(
                user_id=user.user_id,
                service_name="google_drive",
                access_token=encrypted_access,
                refresh_token=encrypted_refresh,
                token_expiry=token_expiry,
                total_space=total_space,
                used_space=used_space
            )
            db.add(cloud_service)
        
        db.commit()
        
        # Create JWT for our app
        access_token = create_access_token(data={"sub": str(user.user_id)})
        
        # Redirect back to frontend callback which stores JWT and routes to dashboard
        frontend_url = os.getenv("FRONTEND_URL", "http://localhost:3000")
        callback_url = f"{frontend_url}/oauth-callback.html#provider=google_drive&token={access_token}&email={user.email}"
        return RedirectResponse(url=callback_url, status_code=302)
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error during Google OAuth: {str(e)}"
        )

@router.get("/dropbox/login")
def dropbox_login():
    """Redirect user to Dropbox OAuth consent screen"""
    if not DROPBOX_CLIENT_ID:
        raise HTTPException(status_code=500, detail="DROPBOX_CLIENT_ID not configured")
    auth_url = "https://www.dropbox.com/oauth2/authorize"
    params = {
        "client_id": DROPBOX_CLIENT_ID,
        "redirect_uri": DROPBOX_REDIRECT_URI,
        "response_type": "code",
        "token_access_type": "offline",
        # request both read + write content scopes for upload/download
        "scope": "files.metadata.read files.content.read files.content.write account_info.read",
        # force user to reapprove so new scopes are granted if already connected without them
        "force_reapprove": "true"
    }
    
    return {"auth_url": f"{auth_url}?{urlencode(params)}"}

@router.get("/dropbox/callback")
def dropbox_callback(code: str, db: Session = Depends(get_db)):
    """Handle Dropbox OAuth callback (uses client secret)"""
    try:
        # Exchange code for tokens using client secret
        token_url = "https://api.dropboxapi.com/oauth2/token"
        if not DROPBOX_CLIENT_ID or not DROPBOX_CLIENT_SECRET:
            raise HTTPException(status_code=500, detail="Dropbox client not configured")
        data = {
            "code": code,
            "grant_type": "authorization_code",
            "client_id": DROPBOX_CLIENT_ID,
            "client_secret": DROPBOX_CLIENT_SECRET,
            "redirect_uri": DROPBOX_REDIRECT_URI
        }
        
        response = requests.post(token_url, data=data)
        token_data = response.json()
        
        if "error" in token_data:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=token_data["error_description"]
            )
        
        # Get user info from Dropbox
        user_info_url = "https://api.dropboxapi.com/2/users/get_current_account"
        headers = {"Authorization": f"Bearer {token_data['access_token']}"}
        user_info = requests.post(user_info_url, headers=headers).json()
        
        # Get storage info from Dropbox
        space_url = "https://api.dropboxapi.com/2/users/get_space_usage"
        space_info = requests.post(space_url, headers=headers).json()
        
        total_space = space_info.get("allocation", {}).get("allocated", 0)
        used_space = space_info.get("used", 0)
        
        # Find or create user in our database
        user = db.query(User).filter(User.email == user_info["email"]).first()
        if not user:
            # Create user without password for OAuth users
            user = User(email=user_info["email"])
            db.add(user)
            db.commit()
            db.refresh(user)
        
        # Encrypt and store tokens
        encrypted_access = encrypt_token(token_data["access_token"])
        encrypted_refresh = encrypt_token(token_data.get("refresh_token", ""))
        token_expiry = datetime.utcnow() + timedelta(seconds=token_data["expires_in"])
        
        # Create or update cloud service connection
        cloud_service = db.query(UserCloudService).filter(
            UserCloudService.user_id == user.user_id,
            UserCloudService.service_name == "dropbox"
        ).first()
        
        if cloud_service:
            cloud_service.access_token = encrypted_access
            if token_data.get("refresh_token"):
                cloud_service.refresh_token = encrypted_refresh
            cloud_service.token_expiry = token_expiry
            cloud_service.total_space = total_space
            cloud_service.used_space = used_space
            cloud_service.is_active = True
        else:
            cloud_service = UserCloudService(
                user_id=user.user_id,
                service_name="dropbox",
                access_token=encrypted_access,
                refresh_token=encrypted_refresh,
                token_expiry=token_expiry,
                total_space=total_space,
                used_space=used_space
            )
            db.add(cloud_service)
        
        db.commit()
        
        # Create JWT for our app
        access_token = create_access_token(data={"sub": str(user.user_id)})
        
        frontend_url = os.getenv("FRONTEND_URL", "http://localhost:3000")
        callback_url = f"{frontend_url}/oauth-callback.html#provider=dropbox&token={access_token}&email={user.email}"
        return RedirectResponse(url=callback_url, status_code=302)
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error during Dropbox OAuth: {str(e)}"
        )

@router.get("/pkce/verifier/{state}")
def get_pkce_verifier(state: str):
    """Get the PKCE code verifier for a given state (for extension use)"""
    code_verifier = pkce_store.get(state)
    if not code_verifier:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Verifier not found or expired"
        )
    return {"code_verifier": code_verifier}

@router.get("/google/device/start")
def google_device_start(current_user: User = Depends(get_current_user)):
    """Start Google Device Authorization flow. Returns verification URI and user code.
    Requires the caller to be authenticated in this app (so we know which user to attach tokens to).
    """
    device_url = "https://oauth2.googleapis.com/device/code"
    data = {
        "client_id": GOOGLE_CLIENT_ID,
        "scope": "openid email profile https://www.googleapis.com/auth/drive https://www.googleapis.com/auth/drive.file"
    }
    r = requests.post(device_url, data=data)
    payload = r.json()
    if r.status_code != 200:
        raise HTTPException(status_code=r.status_code, detail=payload)

    device_code = payload.get("device_code")
    if not device_code:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="No device_code from Google")

    # Track owner of the device flow to attach tokens later
    device_store[device_code] = {"user_id": str(current_user.user_id), "created_at": time.time()}

    return {
        "verification_uri": payload.get("verification_uri") or payload.get("verification_url"),
        "user_code": payload.get("user_code"),
        "device_code": device_code,
        "interval": payload.get("interval", 5),
        "expires_in": payload.get("expires_in", 600)
    }

@router.get("/google/device/poll")
def google_device_poll(device_code: str, db: Session = Depends(get_db)):
    """Poll Google token endpoint using a device_code. On success, stores tokens
    and space metrics in user_cloud_services and returns status."""
    info = device_store.get(device_code)
    if not info:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Unknown or expired device_code")

    token_url = "https://oauth2.googleapis.com/token"
    data = {
        "client_id": GOOGLE_CLIENT_ID,
        "device_code": device_code,
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code"
    }
    r = requests.post(token_url, data=data)
    payload = r.json()

    if "error" in payload:
        err = payload["error"]
        if err in ("authorization_pending", "slow_down"):
            # Client should wait and retry
            return JSONResponse(status_code=202, content={"status": err, "interval": payload.get("interval", 5)})
        if err == "expired_token":
            device_store.pop(device_code, None)
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Device code expired")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=payload)

    # Success: we have access_token (+ optional refresh_token)
    access = payload.get("access_token")
    refresh = payload.get("refresh_token", "")
    expires_in = payload.get("expires_in", 3600)

    # Get user info + storage quota
    headers = {"Authorization": f"Bearer {access}"}
    user_info = requests.get("https://www.googleapis.com/oauth2/v3/userinfo", headers=headers).json()
    drive_info = requests.get("https://www.googleapis.com/drive/v3/about", headers=headers, params={"fields": "storageQuota"}).json()

    storage_quota = drive_info.get("storageQuota", {})
    total_space = int(storage_quota.get("limit", 0) or 0)
    used_space = int(storage_quota.get("usage", 0) or 0)

    # Lookup or create app user (by email); prefer binding to owner in device_store
    user = db.query(User).filter(User.user_id == info["user_id"]).first()
    if not user and user_info.get("email"):
        user = db.query(User).filter(User.email == user_info["email"]).first()
    if not user:
        user = User(email=user_info.get("email") or f"user-{info['user_id']}@example.local")
        db.add(user)
        db.commit()
        db.refresh(user)

    # Encrypt and store
    from .utils import encrypt_token
    token_expiry = datetime.utcnow() + timedelta(seconds=expires_in)
    encrypted_access = encrypt_token(access)
    encrypted_refresh = encrypt_token(refresh)

    cloud_service = db.query(UserCloudService).filter(
        UserCloudService.user_id == user.user_id,
        UserCloudService.service_name == "google_drive"
    ).first()

    if cloud_service:
        cloud_service.access_token = encrypted_access
        if refresh:
            cloud_service.refresh_token = encrypted_refresh
        cloud_service.token_expiry = token_expiry
        cloud_service.total_space = total_space
        cloud_service.used_space = used_space
        cloud_service.is_active = True
    else:
        cloud_service = UserCloudService(
            user_id=user.user_id,
            service_name="google_drive",
            access_token=encrypted_access,
            refresh_token=encrypted_refresh,
            token_expiry=token_expiry,
            total_space=total_space,
            used_space=used_space
        )
        db.add(cloud_service)

    db.commit()
    # Done
    device_store.pop(device_code, None)
    return {"status": "ok", "email": user.email}
