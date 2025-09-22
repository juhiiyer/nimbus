from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
import requests
from datetime import datetime, timedelta
import os

from .database import get_db, UserCloudService
from .schemas import UploadURLRequest, UploadURLResponse, DownloadURLRequest, DownloadURLResponse
from .utils import decrypt_token, validate_token_expiry, encrypt_token
from .auth import get_current_user

# Create the router instance
router = APIRouter(prefix="/services", tags=["services"])

def refresh_google_token(cloud_service: UserCloudService, db: Session):
    """Refresh Google access token if expired using PKCE flow"""
    try:
        if validate_token_expiry(cloud_service.token_expiry):
            return decrypt_token(cloud_service.access_token)
        
        # For PKCE flow, we can't refresh tokens without user interaction
        # The extension will need to re-authenticate
        cloud_service.is_active = False
        db.commit()
        
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Google token expired. Please re-authenticate."
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error refreshing Google token: {str(e)}"
        )

def refresh_dropbox_token(cloud_service: UserCloudService, db: Session):
    """Refresh Dropbox access token if expired (Dropbox uses client secret)"""
    try:
        if validate_token_expiry(cloud_service.token_expiry):
            return decrypt_token(cloud_service.access_token)
        
        # Token expired, refresh it using client secret
        token_url = "https://api.dropboxapi.com/oauth2/token"
        data = {
            "grant_type": "refresh_token",
            "refresh_token": decrypt_token(cloud_service.refresh_token),
            "client_id": os.getenv("DROPBOX_CLIENT_ID"),
            "client_secret": os.getenv("DROPBOX_CLIENT_SECRET")
        }
        
        response = requests.post(token_url, data=data)
        token_data = response.json()
        
        if "error" in token_data:
            # Mark as inactive if refresh fails
            cloud_service.is_active = False
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Failed to refresh Dropbox token. Please re-authenticate."
            )
        
        # Update tokens in database
        cloud_service.access_token = encrypt_token(token_data["access_token"])
        cloud_service.token_expiry = datetime.utcnow() + timedelta(seconds=token_data["expires_in"])
        
        # Dropbox may return a new refresh token
        if "refresh_token" in token_data:
            cloud_service.refresh_token = encrypt_token(token_data["refresh_token"])
        
        db.commit()
        
        return token_data["access_token"]
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error refreshing Dropbox token: {str(e)}"
        )

@router.post("/upload-url", response_model=UploadURLResponse)
def get_upload_url(request: UploadURLRequest, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    """Get a pre-authorized upload URL for a cloud service"""
    # Check if user has enough space
    cloud_service = db.query(UserCloudService).filter(
        UserCloudService.user_id == current_user.user_id,
        UserCloudService.service_name == request.service,
        UserCloudService.is_active == True
    ).first()
    
    if not cloud_service:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"{request.service} not connected or inactive"
        )
    
    # Check storage space
    if cloud_service.used_space + request.filesize > cloud_service.total_space:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Not enough storage space"
        )
    
    try:
        if request.service == "google_drive":
            # Refresh token if needed
            access_token = refresh_google_token(cloud_service, db)
            
            # Create Google Drive upload session
            headers = {
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            }
            data = {
                "name": request.filename,
                "mimeType": "application/octet-stream"
            }
            response = requests.post(
                "https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable",
                headers=headers,
                json=data
            )
            
            if response.status_code != 200:
                raise HTTPException(
                    status_code=response.status_code,
                    detail="Failed to create Google Drive upload session"
                )
            
            upload_url = response.headers.get("Location")
            return UploadURLResponse(upload_url=upload_url)
            
        elif request.service == "dropbox":
            # Refresh token if needed
            access_token = refresh_dropbox_token(cloud_service, db)
            
            # Create Dropbox upload session
            headers = {
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/octet-stream",
                "Dropbox-API-Arg": f'{{"close": false}}'
            }
            
            # Start upload session
            response = requests.post(
                "https://content.dropboxapi.com/2/files/upload_session/start",
                headers=headers
            )
            
            if response.status_code != 200:
                raise HTTPException(
                    status_code=response.status_code,
                    detail="Failed to create Dropbox upload session"
                )
            
            session_id = response.json().get("session_id")
            
            # For the frontend, we'll return the session info
            # The frontend will handle the chunked upload
            upload_info = {
                "session_id": session_id,
                "access_token": access_token,
                "offset": 0,
                "filename": request.filename
            }
            
            return UploadURLResponse(upload_url=str(upload_info))
            
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Unsupported cloud service"
            )
            
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error creating upload URL: {str(e)}"
        )

@router.post("/download-url", response_model=DownloadURLResponse)
def get_download_url(request: DownloadURLRequest, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    """Get a pre-authorized download URL for a file"""
    cloud_service = db.query(UserCloudService).filter(
        UserCloudService.user_id == current_user.user_id,
        UserCloudService.service_name == request.service,
        UserCloudService.is_active == True
    ).first()
    
    if not cloud_service:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"{request.service} not connected or inactive"
        )
    
    try:
        if request.service == "google_drive":
            # Refresh token if needed
            access_token = refresh_google_token(cloud_service, db)
            
            # Get file metadata to get the name
            headers = {"Authorization": f"Bearer {access_token}"}
            meta_response = requests.get(
                f"https://www.googleapis.com/drive/v3/files/{request.file_id}",
                headers=headers
            )
            
            if meta_response.status_code != 200:
                raise HTTPException(
                    status_code=meta_response.status_code,
                    detail="Failed to get file metadata from Google Drive"
                )
            
            file_metadata = meta_response.json()
            filename = file_metadata.get("name", "file")
            
            # Get download URL
            download_url = f"https://www.googleapis.com/drive/v3/files/{request.file_id}?alt=media"
            
            return DownloadURLResponse(download_url=download_url, filename=filename)
            
        elif request.service == "dropbox":
            # Refresh token if needed
            access_token = refresh_dropbox_token(cloud_service, db)
            
            # Get Dropbox temporary link
            headers = {
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            }
            data = {"path": request.file_id}
            
            response = requests.post(
                "https://api.dropboxapi.com/2/files/get_temporary_link",
                headers=headers,
                json=data
            )
            
            if response.status_code != 200:
                raise HTTPException(
                    status_code=response.status_code,
                    detail="Failed to get Dropbox download URL"
                )
            
            result = response.json()
            download_url = result.get("link")
            filename = request.file_id.split("/")[-1] if "/" in request.file_id else request.file_id
            
            return DownloadURLResponse(download_url=download_url, filename=filename)
            
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Unsupported cloud service"
            )
            
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error creating download URL: {str(e)}"
        )

@router.post("/upload-complete")
def upload_complete(service: str, file_size: int, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    """Update storage space after successful upload"""
    cloud_service = db.query(UserCloudService).filter(
        UserCloudService.user_id == current_user.user_id,
        UserCloudService.service_name == service,
        UserCloudService.is_active == True
    ).first()
    
    if cloud_service:
        cloud_service.used_space += file_size
        db.commit()
    
    return {"status": "success", "message": "Storage updated"}

@router.get("/storage/{service}")
def get_storage_info(service: str, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    """Get storage information for a specific cloud service"""
    cloud_service = db.query(UserCloudService).filter(
        UserCloudService.user_id == current_user.user_id,
        UserCloudService.service_name == service,
        UserCloudService.is_active == True
    ).first()
    
    if not cloud_service:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"{service} not connected or inactive"
        )
    
    return {
        "service": service,
        "total_space": cloud_service.total_space,
        "used_space": cloud_service.used_space,
        "available_space": cloud_service.total_space - cloud_service.used_space,
        "is_active": cloud_service.is_active
    }