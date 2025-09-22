from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
import requests
from datetime import datetime, timedelta
import os
import json

from .database import get_db, UserCloudService
from .schemas import UploadURLRequest, UploadURLResponse, DownloadURLRequest, DownloadURLResponse
from .utils import decrypt_token, validate_token_expiry, encrypt_token
from .auth import get_current_user
from fastapi import UploadFile, File, Form
from fastapi.responses import StreamingResponse

# Create the router instance
router = APIRouter(prefix="/services", tags=["services"])

def refresh_google_token(cloud_service: UserCloudService, db: Session):
    """Refresh Google access token if expired using refresh_token (PKCE public client)."""
    try:
        # If token still valid, return decrypted access token
        if validate_token_expiry(cloud_service.token_expiry):
            return decrypt_token(cloud_service.access_token)

        refresh_token = decrypt_token(cloud_service.refresh_token) if cloud_service.refresh_token else None
        if not refresh_token:
            # No refresh token stored; mark inactive
            cloud_service.is_active = False
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Google token expired and no refresh token available. Please re-authenticate."
            )

        # Refresh using client_id (no client_secret required for PKCE public client)
        token_url = "https://oauth2.googleapis.com/token"
        data = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": os.getenv("GOOGLE_CLIENT_ID")
        }
        client_secret = os.getenv("GOOGLE_CLIENT_SECRET")
        if client_secret:
            data["client_secret"] = client_secret
        response = requests.post(token_url, data=data)
        token_data = response.json()

        if "error" in token_data or "access_token" not in token_data:
            cloud_service.is_active = False
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Failed to refresh Google token: {token_data.get('error_description') or token_data}"
            )

        # Update tokens/expiry
        cloud_service.access_token = encrypt_token(token_data["access_token"])
        if token_data.get("refresh_token"):
            cloud_service.refresh_token = encrypt_token(token_data["refresh_token"])
        expires_in = token_data.get("expires_in", 3600)
        cloud_service.token_expiry = datetime.utcnow() + timedelta(seconds=expires_in)
        cloud_service.is_active = True
        db.commit()
        return token_data["access_token"]

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

@router.get("/download")
def direct_download(service: str, file_id: str, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    """Stream a file directly to the browser with proper auth, so downloads work for Google Drive and Dropbox.
    The browser will GET /services/download?service=google_drive&file_id=abc (or dropbox with a path).
    """
    cloud_service = db.query(UserCloudService).filter(
        UserCloudService.user_id == current_user.user_id,
        UserCloudService.service_name == service,
        UserCloudService.is_active == True
    ).first()

    if not cloud_service:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"{service} not connected or inactive")

    try:
        if service == "google_drive":
            access_token = refresh_google_token(cloud_service, db)
            # Fetch file metadata for filename
            meta = requests.get(
                f"https://www.googleapis.com/drive/v3/files/{file_id}",
                headers={"Authorization": f"Bearer {access_token}"},
                params={"fields": "name"}
            )
            filename = "file"
            if meta.status_code == 200:
                filename = meta.json().get("name", filename)
            # Stream bytes with Authorization header
            r = requests.get(
                f"https://www.googleapis.com/drive/v3/files/{file_id}?alt=media",
                headers={"Authorization": f"Bearer {access_token}"},
                stream=True
            )
            if r.status_code != 200:
                raise HTTPException(status_code=r.status_code, detail="Google Drive download failed")
            return StreamingResponse(r.raw, media_type=r.headers.get("Content-Type", "application/octet-stream"), headers={
                "Content-Disposition": f"attachment; filename=\"{filename}\""
            })
        elif service == "dropbox":
            access_token = refresh_dropbox_token(cloud_service, db)
            # Get a temporary link and stream the bytes
            temp = requests.post(
                "https://api.dropboxapi.com/2/files/get_temporary_link",
                headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"},
                json={"path": file_id}
            )
            if temp.status_code != 200:
                raise HTTPException(status_code=temp.status_code, detail="Failed to get Dropbox temporary link")
            data = temp.json()
            link = data.get("link")
            filename = (data.get("metadata") or {}).get("name", "file")
            r = requests.get(link, stream=True)
            if r.status_code != 200:
                raise HTTPException(status_code=r.status_code, detail="Dropbox download failed")
            return StreamingResponse(r.raw, media_type=r.headers.get("Content-Type", "application/octet-stream"), headers={
                "Content-Disposition": f"attachment; filename=\"{filename}\""
            })
        else:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unsupported cloud service")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Download error: {str(e)}")

@router.get("/list")
def list_files(service: str, cursor: str = None, page_token: str = None, page_size: int = 50, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    """List files metadata for indexing. Supports Dropbox and Google Drive.
    - Dropbox: uses list_folder (cursor for pagination)
    - Google Drive: uses files.list (page_token for pagination)
    Returns a normalized list and a next cursor/token.
    """
    cloud_service = db.query(UserCloudService).filter(
        UserCloudService.user_id == current_user.user_id,
        UserCloudService.service_name == service,
        UserCloudService.is_active == True
    ).first()

    if not cloud_service:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"{service} not connected or inactive")

    try:
        items = []
        next_token = None
        if service == "dropbox":
            access_token = refresh_dropbox_token(cloud_service, db)
            headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}
            if cursor:
                url = "https://api.dropboxapi.com/2/files/list_folder/continue"
                data = {"cursor": cursor}
            else:
                url = "https://api.dropboxapi.com/2/files/list_folder"
                data = {"path": "", "recursive": True, "include_non_downloadable_files": False, "limit": page_size}
            response = requests.post(url, headers=headers, json=data)
            if response.status_code != 200:
                raise HTTPException(status_code=response.status_code, detail="Dropbox list failed")
            payload = response.json()
            for e in payload.get("entries", []):
                if e.get(".tag") == "file":
                    items.append({
                        "id": e.get("id"),
                        "name": e.get("name"),
                        "size": e.get("size"),
                        "mimeType": None,
                        "path": e.get("path_lower"),
                        "service": "dropbox"
                    })
            next_token = payload.get("cursor") if payload.get("has_more") else None
        elif service == "google_drive":
            access_token = refresh_google_token(cloud_service, db)
            headers = {"Authorization": f"Bearer {access_token}"}
            params = {
                "pageSize": page_size,
                "fields": "nextPageToken, files(id,name,mimeType,size)",
                "q": "trashed=false"
            }
            if page_token:
                params["pageToken"] = page_token
            response = requests.get("https://www.googleapis.com/drive/v3/files", headers=headers, params=params)
            if response.status_code != 200:
                raise HTTPException(status_code=response.status_code, detail="Google Drive list failed")
            payload = response.json()
            for f in payload.get("files", []):
                items.append({
                    "id": f.get("id"),
                    "name": f.get("name"),
                    "size": int(f.get("size", 0)) if f.get("size") is not None else None,
                    "mimeType": f.get("mimeType"),
                    "path": None,
                    "service": "google_drive"
                })
            next_token = payload.get("nextPageToken")
        else:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unsupported cloud service")
        return {"items": items, "next": next_token}
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Error listing files: {str(e)}")

@router.get("/search")
def search_files(service: str, q: str, limit: int = 20, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    """Search files in a connected cloud service (Dropbox only for now)."""
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

    try:
        if service == "dropbox":
            access_token = refresh_dropbox_token(cloud_service, db)
            headers = {
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            }
            data = {
                "query": q,
                "options": {
                    "max_results": limit
                }
            }
            response = requests.post(
                "https://api.dropboxapi.com/2/files/search_v2",
                headers=headers,
                json=data
            )
            if response.status_code != 200:
                raise HTTPException(status_code=response.status_code, detail="Dropbox search failed")

            results = response.json().get("matches", [])
            items = []
            for m in results:
                md = (m.get("metadata", {}) or {}).get("metadata", {})
                items.append({
                    "id": md.get("id"),
                    "name": md.get("name"),
                    "path": md.get("path_lower"),
                    "tag": md.get(".tag"),
                    "size": md.get("size")
                })
            return {"items": items}
        else:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unsupported cloud service for search")
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Error searching files: {str(e)}")

@router.post("/upload-simple")
async def upload_simple(service: str = Form("auto"), db: Session = Depends(get_db), current_user: dict = Depends(get_current_user), file: UploadFile = File(...)):
    """Simple upload path for small files (<150MB). If service=auto, choose destination by max available space.
    Returns {service, filename, size} on success.
    """
    # Choose service if auto
    chosen_service = service
    if service == "auto":
        # Pick the connected service with maximum available space
        services = db.query(UserCloudService).filter(
            UserCloudService.user_id == current_user.user_id,
            UserCloudService.is_active == True
        ).all()
        if not services:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No connected services")
        best = max(services, key=lambda s: (s.total_space - s.used_space))
        chosen_service = best.service_name

    # Fetch the cloud_service row for chosen_service
    cloud_service = db.query(UserCloudService).filter(
        UserCloudService.user_id == current_user.user_id,
        UserCloudService.service_name == chosen_service,
        UserCloudService.is_active == True
    ).first()
    if not cloud_service:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"{chosen_service} not connected or inactive")

    content = await file.read()
    size = len(content)

    try:
        CHUNK = 5 * 1024 * 1024  # 5MB
        if chosen_service == "dropbox":
            access_token = refresh_dropbox_token(cloud_service, db)
            if size <= CHUNK:
                # simple upload
                headers = {
                    "Authorization": f"Bearer {access_token}",
                    "Content-Type": "application/octet-stream",
                    "Dropbox-API-Arg": json.dumps({
                        "path": f"/{file.filename}",
                        "mode": "add",
                        "autorename": True,
                        "mute": False,
                        "strict_conflict": False
                    })
                }
                resp = requests.post("https://content.dropboxapi.com/2/files/upload", headers=headers, data=content)
            else:
                # chunked upload session
                start = requests.post(
                    "https://content.dropboxapi.com/2/files/upload_session/start",
                    headers={
                        "Authorization": f"Bearer {access_token}",
                        "Content-Type": "application/octet-stream",
                        "Dropbox-API-Arg": json.dumps({"close": False})
                    },
                    data=content[0:CHUNK]
                )
                if start.status_code != 200:
                    try:
                        err = start.json(); summary = err.get("error_summary") or json.dumps(err)
                    except Exception:
                        summary = start.text
                    raise HTTPException(status_code=start.status_code, detail=f"Dropbox upload failed: {summary}")
                session_id = start.json()["session_id"]
                offset = CHUNK
                while offset < size:
                    chunk = content[offset: offset + CHUNK]
                    append = requests.post(
                        "https://content.dropboxapi.com/2/files/upload_session/append_v2",
                        headers={
                            "Authorization": f"Bearer {access_token}",
                            "Content-Type": "application/octet-stream",
                            "Dropbox-API-Arg": json.dumps({"cursor": {"session_id": session_id, "offset": offset}})
                        },
                        data=chunk
                    )
                    if append.status_code != 200:
                        try:
                            err = append.json(); summary = err.get("error_summary") or json.dumps(err)
                        except Exception:
                            summary = append.text
                        raise HTTPException(status_code=append.status_code, detail=f"Dropbox upload failed: {summary}")
                    offset += len(chunk)
                finish = requests.post(
                    "https://content.dropboxapi.com/2/files/upload_session/finish",
                    headers={
                        "Authorization": f"Bearer {access_token}",
                        "Content-Type": "application/octet-stream",
                        "Dropbox-API-Arg": json.dumps({
                            "cursor": {"session_id": session_id, "offset": size},
                            "commit": {"path": f"/{file.filename}", "mode": "add", "autorename": True}
                        })
                    }
                )
                resp = finish
            if resp.status_code not in (200, 201):
                # Surface Dropbox API error payload for easier debugging on the client
                try:
                    err = resp.json()
                    summary = err.get("error_summary") or json.dumps(err)
                except Exception:
                    summary = resp.text
                raise HTTPException(status_code=resp.status_code, detail=f"Dropbox upload failed: {summary}")
            meta = resp.json()
            new_id = meta.get("id")
            new_path = meta.get("path_lower") or meta.get("path_display")
        elif chosen_service == "google_drive":
            access_token = refresh_google_token(cloud_service, db)
            if size <= CHUNK:
                headers = {"Authorization": f"Bearer {access_token}"}
                metadata = {"name": file.filename}
                files = {
                    'metadata': ('metadata', json.dumps(metadata), 'application/json; charset=UTF-8'),
                    'file': (file.filename, content, file.content_type or 'application/octet-stream')
                }
                resp = requests.post("https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart", headers=headers, files=files)
            else:
                # Resumable upload
                init = requests.post(
                    "https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable",
                    headers={
                        "Authorization": f"Bearer {access_token}",
                        "Content-Type": "application/json; charset=UTF-8"
                    },
                    json={"name": file.filename}
                )
                if init.status_code not in (200, 201):
                    try:
                        err = init.json(); summary = (err.get("error") or {}).get("message") or json.dumps(err)
                    except Exception:
                        summary = init.text
                    raise HTTPException(status_code=init.status_code, detail=f"Google Drive upload failed: {summary}")
                location = init.headers.get("Location")
                offset = 0
                while offset < size:
                    chunk = content[offset: offset + CHUNK]
                    end = offset + len(chunk) - 1
                    headers = {
                        "Authorization": f"Bearer {access_token}",
                        "Content-Length": str(len(chunk)),
                        "Content-Range": f"bytes {offset}-{end}/{size}"
                    }
                    put = requests.put(location, headers=headers, data=chunk)
                    if put.status_code not in (200, 201, 308):
                        try:
                            err = put.json(); summary = (err.get("error") or {}).get("message") or json.dumps(err)
                        except Exception:
                            summary = put.text
                        raise HTTPException(status_code=put.status_code, detail=f"Google Drive upload failed: {summary}")
                    offset += len(chunk)
                resp = put
            if resp.status_code not in (200, 201):
                try:
                    err = resp.json()
                    summary = err.get("error", {}).get("message") or json.dumps(err)
                except Exception:
                    summary = resp.text
                raise HTTPException(status_code=resp.status_code, detail=f"Google Drive upload failed: {summary}")
            meta = resp.json() if resp.content else {}
            new_id = meta.get("id")
            new_path = None
        else:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unsupported cloud service")

        # Update used_space
        cloud_service.used_space += size
        db.commit()
        return {"service": chosen_service, "filename": file.filename, "size": size, "id": new_id, "path": new_path}
    except HTTPException as e:
        # If auto was selected and we hit a permission/scope issue, try the other provider automatically
        if service == "auto":
            err_text = str(getattr(e, 'detail', e)).lower()
            permission_problem = any(x in err_text for x in [
                "invalid_access_token", "expired", "permission", "scope", "forbidden", "unauthorized", "content.write", "insufficient"
            ]) or getattr(e, 'status_code', None) in (401, 403)
            if permission_problem:
                other_service_name = "google_drive" if chosen_service == "dropbox" else "dropbox"
                other = db.query(UserCloudService).filter(
                    UserCloudService.user_id == current_user.user_id,
                    UserCloudService.service_name == other_service_name,
                    UserCloudService.is_active == True
                ).first()
                if other:
                    try:
                        if other_service_name == "dropbox":
                            access_token = refresh_dropbox_token(other, db)
                            headers = {
                                "Authorization": f"Bearer {access_token}",
                                "Content-Type": "application/octet-stream",
                                "Dropbox-API-Arg": json.dumps({
                                    "path": f"/{file.filename}",
                                    "mode": "add",
                                    "autorename": True,
                                    "mute": False,
                                    "strict_conflict": False
                                })
                            }
                            resp = requests.post("https://content.dropboxapi.com/2/files/upload", headers=headers, data=content)
                            if resp.status_code not in (200, 201):
                                try:
                                    err = resp.json(); summary = err.get("error_summary") or json.dumps(err)
                                except Exception:
                                    summary = resp.text
                                raise HTTPException(status_code=resp.status_code, detail=f"Dropbox upload failed: {summary}")
                            meta = resp.json(); new_id = meta.get("id"); new_path = meta.get("path_lower") or meta.get("path_display")
                        else:
                            access_token = refresh_google_token(other, db)
                            headers = {"Authorization": f"Bearer {access_token}"}
                            metadata = {"name": file.filename}
                            files = {
                                'metadata': ('metadata', json.dumps(metadata), 'application/json; charset=UTF-8'),
                                'file': (file.filename, content, file.content_type or 'application/octet-stream')
                            }
                            resp = requests.post("https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart", headers=headers, files=files)
                            if resp.status_code not in (200, 201):
                                try:
                                    err = resp.json(); summary = (err.get("error") or {}).get("message") or json.dumps(err)
                                except Exception:
                                    summary = resp.text
                                raise HTTPException(status_code=resp.status_code, detail=f"Google Drive upload failed: {summary}")
                            meta = resp.json(); new_id = meta.get("id"); new_path = None
                        other.used_space += size
                        db.commit()
                        return {"service": other_service_name, "filename": file.filename, "size": size, "id": new_id, "path": new_path}
                    except HTTPException:
                        pass
        # Otherwise bubble up the original error
        raise
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Upload error: {str(e)}")
