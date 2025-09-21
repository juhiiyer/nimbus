from pydantic import BaseModel, EmailStr
from uuid import UUID
from datetime import datetime
from typing import Optional, List

class UserCreate(BaseModel):
    """Schema for user registration"""
    email: EmailStr
    password: str

class UserOut(BaseModel):
    """Schema for user response (without password)"""
    user_id: UUID
    email: EmailStr
    created_at: datetime

    class Config:
        from_attributes = True

class Token(BaseModel):
    """Schema for JWT token response"""
    access_token: str
    token_type: str = "bearer"

class CloudServiceBase(BaseModel):
    """Base schema for cloud service"""
    service_name: str

class CloudServiceCreate(CloudServiceBase):
    """Schema for creating a cloud service connection"""
    access_token: str
    refresh_token: str
    token_expiry: datetime
    total_space: int
    used_space: int

class CloudServiceOut(CloudServiceBase):
    """Schema for cloud service response"""
    id: UUID
    user_id: UUID
    is_active: bool
    total_space: int
    used_space: int

    class Config:
        from_attributes = True

class UploadURLRequest(BaseModel):
    """Schema for requesting an upload URL"""
    filename: str
    filesize: int
    service: str

class UploadURLResponse(BaseModel):
    """Schema for upload URL response"""
    upload_url: str

class DownloadURLRequest(BaseModel):
    """Schema for requesting a download URL"""
    file_id: str
    service: str

class DownloadURLResponse(BaseModel):
    """Schema for download URL response"""
    download_url: str
    filename: str