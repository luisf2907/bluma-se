from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from fastapi import HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import secrets
from database import get_db_connection, verify_password

# Configurações JWT
SECRET_KEY = "bluma_news_secret_key_2025_very_secure"  # Em produção, usar variável de ambiente
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

security = HTTPBearer()

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Cria um token JWT"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(token: str):
    """Verifica se o token JWT é válido"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: int = payload.get("sub")
        if user_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token inválido",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return user_id
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido",
            headers={"WWW-Authenticate": "Bearer"},
        )

def authenticate_user(email: str, password: str):
    """Autentica um usuário"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT id, name, email, password_hash, role, avatar, is_active 
        FROM users WHERE email = ? AND is_active = 1
    """, (email,))
    
    user = cursor.fetchone()
    conn.close()
    
    if not user:
        return False
    
    if not verify_password(password, user['password_hash']):
        return False
    
    return dict(user)

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Obtém o usuário atual baseado no token"""
    token = credentials.credentials
    user_id = verify_token(token)
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT id, name, email, role, avatar, is_active, created_at
        FROM users WHERE id = ? AND is_active = 1
    """, (user_id,))
    
    user = cursor.fetchone()
    conn.close()
    
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuário não encontrado",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return dict(user)

def get_current_active_user(current_user: dict = Depends(get_current_user)):
    """Obtém o usuário atual ativo"""
    if not current_user['is_active']:
        raise HTTPException(status_code=400, detail="Usuário inativo")
    return current_user

def require_admin(current_user: dict = Depends(get_current_active_user)):
    """Requer que o usuário seja admin"""
    if current_user['role'] != 'admin':
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Acesso negado: privilégios de administrador necessários"
        )
    return current_user

def require_editor_or_admin(current_user: dict = Depends(get_current_active_user)):
    """Requer que o usuário seja editor ou admin"""
    if current_user['role'] not in ['editor', 'admin']:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Acesso negado: privilégios de editor ou administrador necessários"
        )
    return current_user
