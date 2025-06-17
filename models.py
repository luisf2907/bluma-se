from pydantic import BaseModel, EmailStr
from typing import Optional, Literal
from datetime import datetime

# Modelos para requisições
class UserCreate(BaseModel):
    name: str
    email: EmailStr
    password: str
    role: Optional[Literal["user", "editor", "admin"]] = "user"
    avatar: Optional[str] = "👤"

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserUpdate(BaseModel):
    name: Optional[str] = None
    email: Optional[EmailStr] = None
    role: Optional[Literal["user", "editor", "admin"]] = None
    avatar: Optional[str] = None
    is_active: Optional[bool] = None

class PasswordChange(BaseModel):
    current_password: str
    new_password: str

# Modelos para respostas
class UserResponse(BaseModel):
    id: int
    name: str
    email: str
    role: str
    avatar: str
    is_active: bool
    created_at: datetime
    
    class Config:
        from_attributes = True

class UserPublic(BaseModel):
    id: int
    name: str
    email: str
    role: str
    avatar: str
    
    class Config:
        from_attributes = True

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserPublic

class ArticleCreate(BaseModel):
    title: str
    summary: Optional[str] = None
    content: Optional[str] = None
    image_url: Optional[str] = None
    category: Optional[str] = None
    is_published: Optional[bool] = False

class ArticleResponse(BaseModel):
    id: int
    title: str
    summary: Optional[str]
    content: Optional[str]
    image_url: Optional[str]
    category: Optional[str]
    author_id: Optional[int]
    author_name: Optional[str]
    is_published: bool
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True

# Modelos para comentários
class CommentCreate(BaseModel):
    content: str
    article_id: int

class CommentUpdate(BaseModel):
    content: str

class CommentResponse(BaseModel):
    id: int
    content: str
    article_id: int
    author_id: int
    author_name: str
    author_avatar: str
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True
