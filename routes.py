from fastapi import APIRouter, HTTPException, status, Depends
from datetime import timedelta
from typing import List, Optional
from models import (
    UserCreate, UserLogin, UserUpdate, UserResponse, 
    UserPublic, TokenResponse, PasswordChange,
    ArticleCreate, ArticleResponse,
    CommentCreate, CommentUpdate, CommentResponse
)
from auth import (
    authenticate_user, create_access_token, get_current_active_user,
    require_admin, require_editor_or_admin, ACCESS_TOKEN_EXPIRE_MINUTES
)
from database import get_db_connection, hash_password, verify_password

router = APIRouter(prefix="/api/auth", tags=["authentication"])
admin_router = APIRouter(prefix="/api/admin", tags=["admin"])
articles_router = APIRouter(prefix="/api/articles", tags=["articles"])
comments_router = APIRouter(prefix="/api/comments", tags=["comments"])
favorites_router = APIRouter(prefix="/api/favorites", tags=["favorites"])

@router.post("/login", response_model=TokenResponse)
async def login(user_credentials: UserLogin):
    """Login de usuário"""
    user = authenticate_user(user_credentials.email, user_credentials.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email ou senha incorretos",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": str(user["id"])}, expires_delta=access_token_expires
    )
    
    user_public = UserPublic(
        id=user["id"],
        name=user["name"],
        email=user["email"],
        role=user["role"],
        avatar=user["avatar"]
    )
    
    return TokenResponse(
        access_token=access_token,
        user=user_public
    )

@router.post("/register", response_model=TokenResponse)
async def register(user_data: UserCreate):
    """Registro de novo usuário"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Verificar se o email já existe
    cursor.execute("SELECT id FROM users WHERE email = ?", (user_data.email,))
    if cursor.fetchone():
        conn.close()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email já está em uso"
        )
    
    # Criar novo usuário
    password_hash = hash_password(user_data.password)
    cursor.execute("""
        INSERT INTO users (name, email, password_hash, role, avatar)
        VALUES (?, ?, ?, ?, ?)
    """, (user_data.name, user_data.email, password_hash, user_data.role, user_data.avatar))
    
    user_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    # Fazer login automático
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": str(user_id)}, expires_delta=access_token_expires
    )
    
    user_public = UserPublic(
        id=user_id,
        name=user_data.name,
        email=user_data.email,
        role=user_data.role,
        avatar=user_data.avatar
    )
    
    return TokenResponse(
        access_token=access_token,
        user=user_public
    )

@router.get("/me", response_model=UserPublic)
async def get_current_user_info(current_user: dict = Depends(get_current_active_user)):
    """Obter informações do usuário atual"""
    return UserPublic(**current_user)

@router.put("/me", response_model=UserPublic)
async def update_current_user(
    user_update: UserUpdate,
    current_user: dict = Depends(get_current_active_user)
):
    """Atualizar informações do usuário atual"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Verificar se o novo email já está em uso (se fornecido)
    if user_update.email and user_update.email != current_user['email']:
        cursor.execute("SELECT id FROM users WHERE email = ? AND id != ?", 
                      (user_update.email, current_user['id']))
        if cursor.fetchone():
            conn.close()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email já está em uso"
            )
    
    # Atualizar campos fornecidos
    update_fields = []
    update_values = []
    
    if user_update.name is not None:
        update_fields.append("name = ?")
        update_values.append(user_update.name)
    
    if user_update.email is not None:
        update_fields.append("email = ?")
        update_values.append(user_update.email)
    
    if user_update.avatar is not None:
        update_fields.append("avatar = ?")
        update_values.append(user_update.avatar)
    
    if update_fields:
        update_fields.append("updated_at = CURRENT_TIMESTAMP")
        update_values.append(current_user['id'])
        
        query = f"UPDATE users SET {', '.join(update_fields)} WHERE id = ?"
        cursor.execute(query, update_values)
        conn.commit()
    
    # Buscar usuário atualizado
    cursor.execute("""
        SELECT id, name, email, role, avatar, is_active, created_at
        FROM users WHERE id = ?
    """, (current_user['id'],))
    
    updated_user = cursor.fetchone()
    conn.close()
    
    return UserPublic(**dict(updated_user))

@router.post("/change-password")
async def change_password(
    password_data: PasswordChange,
    current_user: dict = Depends(get_current_active_user)
):
    """Alterar senha do usuário"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Verificar senha atual
    cursor.execute("SELECT password_hash FROM users WHERE id = ?", (current_user['id'],))
    user_data = cursor.fetchone()
    
    if not verify_password(password_data.current_password, user_data['password_hash']):
        conn.close()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Senha atual incorreta"
        )
    
    # Atualizar senha
    new_password_hash = hash_password(password_data.new_password)
    cursor.execute("""
        UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP 
        WHERE id = ?
    """, (new_password_hash, current_user['id']))
    
    conn.commit()
    conn.close()
    
    return {"message": "Senha alterada com sucesso"}

# Rotas administrativas
@admin_router.get("/users", response_model=List[UserResponse])
async def list_users(admin_user: dict = Depends(require_admin)):
    """Listar todos os usuários (apenas admin)"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT id, name, email, role, avatar, is_active, created_at
        FROM users ORDER BY created_at DESC
    """)
    
    users = cursor.fetchall()
    conn.close()
    
    return [UserResponse(**dict(user)) for user in users]

@admin_router.post("/users", response_model=UserResponse)
async def create_user(
    user_data: UserCreate,
    admin_user: dict = Depends(require_admin)
):
    """Criar usuário (apenas admin)"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Verificar se o email já existe
    cursor.execute("SELECT id FROM users WHERE email = ?", (user_data.email,))
    if cursor.fetchone():
        conn.close()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email já está em uso"
        )
    
    # Criar usuário
    password_hash = hash_password(user_data.password)
    cursor.execute("""
        INSERT INTO users (name, email, password_hash, role, avatar)
        VALUES (?, ?, ?, ?, ?)
    """, (user_data.name, user_data.email, password_hash, user_data.role, user_data.avatar))
    
    user_id = cursor.lastrowid
    conn.commit()
    
    # Buscar usuário criado
    cursor.execute("""
        SELECT id, name, email, role, avatar, is_active, created_at
        FROM users WHERE id = ?
    """, (user_id,))
    
    new_user = cursor.fetchone()
    conn.close()
    
    return UserResponse(**dict(new_user))

@admin_router.put("/users/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: int,
    user_update: UserUpdate,
    admin_user: dict = Depends(require_admin)
):
    """Atualizar usuário (apenas admin)"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Verificar se o usuário existe
    cursor.execute("SELECT id FROM users WHERE id = ?", (user_id,))
    if not cursor.fetchone():
        conn.close()
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuário não encontrado"
        )
    
    # Verificar se o novo email já está em uso
    if user_update.email:
        cursor.execute("SELECT id FROM users WHERE email = ? AND id != ?", 
                      (user_update.email, user_id))
        if cursor.fetchone():
            conn.close()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email já está em uso"
            )
    
    # Atualizar campos fornecidos
    update_fields = []
    update_values = []
    
    for field, value in user_update.dict(exclude_none=True).items():
        update_fields.append(f"{field} = ?")
        update_values.append(value)
    
    if update_fields:
        update_fields.append("updated_at = CURRENT_TIMESTAMP")
        update_values.append(user_id)
        
        query = f"UPDATE users SET {', '.join(update_fields)} WHERE id = ?"
        cursor.execute(query, update_values)
        conn.commit()
    
    # Buscar usuário atualizado
    cursor.execute("""
        SELECT id, name, email, role, avatar, is_active, created_at
        FROM users WHERE id = ?
    """, (user_id,))
    
    updated_user = cursor.fetchone()
    conn.close()
    
    return UserResponse(**dict(updated_user))

@admin_router.delete("/users/{user_id}")
async def delete_user(
    user_id: int,
    admin_user: dict = Depends(require_admin)
):
    """Deletar usuário (apenas admin)"""
    if user_id == admin_user['id']:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Não é possível deletar sua própria conta"
        )
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
    
    if cursor.rowcount == 0:
        conn.close()
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuário não encontrado"
        )
    
    conn.commit()
    conn.close()
    
    return {"message": "Usuário deletado com sucesso"}

# Rotas de artigos
@articles_router.post("/", response_model=ArticleResponse)
async def create_article(
    article_data: ArticleCreate,
    current_user: dict = Depends(require_editor_or_admin)
):
    """Criar um novo artigo (editor ou admin)"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        INSERT INTO articles (title, summary, content, image_url, category, author_id, is_published)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        article_data.title,
        article_data.summary,
        article_data.content,
        article_data.image_url,
        article_data.category,
        current_user['id'],
        article_data.is_published
    ))
    
    article_id = cursor.lastrowid
    conn.commit()
    
    # Buscar artigo criado com informações do autor
    cursor.execute("""
        SELECT a.*, u.name as author_name
        FROM articles a
        LEFT JOIN users u ON a.author_id = u.id
        WHERE a.id = ?
    """, (article_id,))
    
    new_article = cursor.fetchone()
    conn.close()
    
    return ArticleResponse(**dict(new_article))

@articles_router.get("/", response_model=List[ArticleResponse])
async def list_articles(
    published_only: bool = True,
    category: Optional[str] = None
):
    """Listar artigos"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    query = """
        SELECT a.*, u.name as author_name
        FROM articles a
        LEFT JOIN users u ON a.author_id = u.id
    """
    params = []
    conditions = []
    
    if published_only:
        conditions.append("a.is_published = 1")
    
    if category:
        conditions.append("a.category = ?")
        params.append(category)
    
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    
    query += " ORDER BY a.created_at DESC"
    
    cursor.execute(query, params)
    articles = cursor.fetchall()
    conn.close()
    
    return [ArticleResponse(**dict(article)) for article in articles]

@articles_router.get("/my", response_model=List[ArticleResponse])
async def get_my_articles(current_user: dict = Depends(get_current_active_user)):
    """Listar artigos do usuário atual"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT a.*, u.name as author_name
        FROM articles a
        LEFT JOIN users u ON a.author_id = u.id
        WHERE a.author_id = ?
        ORDER BY a.created_at DESC
    """, (current_user["id"],))
    
    articles = cursor.fetchall()
    conn.close()
    
    return [ArticleResponse(**dict(article)) for article in articles]

@articles_router.get("/{article_id}", response_model=ArticleResponse)
async def get_article(article_id: int):
    """Obter um artigo específico"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT a.*, u.name as author_name
        FROM articles a
        LEFT JOIN users u ON a.author_id = u.id
        WHERE a.id = ?
    """, (article_id,))
    
    article = cursor.fetchone()
    conn.close()
    
    if not article:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Artigo não encontrado"
        )
    
    return ArticleResponse(**dict(article))

@articles_router.put("/{article_id}", response_model=ArticleResponse)
async def update_article(
    article_id: int,
    article_data: ArticleCreate,
    current_user: dict = Depends(require_editor_or_admin)
):
    """Atualizar um artigo (editor/admin ou autor)"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Verificar se o artigo existe e se o usuário tem permissão
    cursor.execute("SELECT author_id FROM articles WHERE id = ?", (article_id,))
    article = cursor.fetchone()
    
    if not article:
        conn.close()
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Artigo não encontrado"
        )
    
    # Apenas o autor ou admin pode editar
    if current_user['role'] not in ['admin'] and article['author_id'] != current_user['id']:
        conn.close()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Sem permissão para editar este artigo"
        )
    
    cursor.execute("""
        UPDATE articles SET 
            title = ?, summary = ?, content = ?, image_url = ?, 
            category = ?, is_published = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
    """, (
        article_data.title,
        article_data.summary,
        article_data.content,
        article_data.image_url,
        article_data.category,
        article_data.is_published,
        article_id
    ))
    
    conn.commit()
    
    # Buscar artigo atualizado
    cursor.execute("""
        SELECT a.*, u.name as author_name
        FROM articles a
        LEFT JOIN users u ON a.author_id = u.id
        WHERE a.id = ?
    """, (article_id,))
    
    updated_article = cursor.fetchone()
    conn.close()
    
    return ArticleResponse(**dict(updated_article))

@articles_router.delete("/{article_id}")
async def delete_article(
    article_id: int,
    current_user: dict = Depends(require_editor_or_admin)
):
    """Deletar um artigo (editor/admin ou autor)"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Verificar se o artigo existe e se o usuário tem permissão
    cursor.execute("SELECT author_id FROM articles WHERE id = ?", (article_id,))
    article = cursor.fetchone()
    
    if not article:
        conn.close()
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Artigo não encontrado"
        )
    
    # Apenas o autor ou admin pode deletar
    if current_user['role'] not in ['admin'] and article['author_id'] != current_user['id']:
        conn.close()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Sem permissão para deletar este artigo"
        )
    
    cursor.execute("DELETE FROM articles WHERE id = ?", (article_id,))
    conn.commit()
    conn.close()
    
    return {"message": "Artigo deletado com sucesso"}

# ===== ROTAS DE COMENTÁRIOS =====

@comments_router.post("/", response_model=CommentResponse)
async def create_comment(
    comment_data: CommentCreate,
    current_user: dict = Depends(get_current_active_user)
):
    """Criar um novo comentário"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Verificar se o artigo existe e está publicado
    cursor.execute("SELECT id, is_published FROM articles WHERE id = ?", (comment_data.article_id,))
    article = cursor.fetchone()
    
    if not article:
        conn.close()
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Artigo não encontrado"
        )
    
    if not article['is_published']:
        conn.close()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Não é possível comentar em artigos não publicados"
        )
    
    # Inserir comentário
    cursor.execute("""
        INSERT INTO comments (content, article_id, author_id)
        VALUES (?, ?, ?)
    """, (comment_data.content, comment_data.article_id, current_user['id']))
    
    comment_id = cursor.lastrowid
    
    # Buscar comentário criado com informações do autor
    cursor.execute("""
        SELECT c.*, u.name as author_name, u.avatar as author_avatar
        FROM comments c
        LEFT JOIN users u ON c.author_id = u.id
        WHERE c.id = ?
    """, (comment_id,))
    
    new_comment = cursor.fetchone()
    conn.commit()
    conn.close()
    
    return CommentResponse(**dict(new_comment))

@comments_router.get("/article/{article_id}", response_model=List[CommentResponse])
async def get_article_comments(article_id: int):
    """Listar comentários de um artigo"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Verificar se o artigo existe
    cursor.execute("SELECT id FROM articles WHERE id = ?", (article_id,))
    if not cursor.fetchone():
        conn.close()
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Artigo não encontrado"
        )
    
    # Buscar comentários
    cursor.execute("""
        SELECT c.*, u.name as author_name, u.avatar as author_avatar
        FROM comments c
        LEFT JOIN users u ON c.author_id = u.id
        WHERE c.article_id = ?
        ORDER BY c.created_at ASC
    """, (article_id,))
    
    comments = cursor.fetchall()
    conn.close()
    
    return [CommentResponse(**dict(comment)) for comment in comments]

@comments_router.put("/{comment_id}", response_model=CommentResponse)
async def update_comment(
    comment_id: int,
    comment_data: CommentUpdate,
    current_user: dict = Depends(get_current_active_user)
):
    """Atualizar comentário (apenas o autor)"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Verificar se o comentário existe e se o usuário é o autor
    cursor.execute("SELECT author_id FROM comments WHERE id = ?", (comment_id,))
    comment = cursor.fetchone()
    
    if not comment:
        conn.close()
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Comentário não encontrado"
        )
    
    if comment['author_id'] != current_user['id']:
        conn.close()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Sem permissão para editar este comentário"
        )
    
    # Atualizar comentário
    cursor.execute("""
        UPDATE comments 
        SET content = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
    """, (comment_data.content, comment_id))
    
    # Buscar comentário atualizado
    cursor.execute("""
        SELECT c.*, u.name as author_name, u.avatar as author_avatar
        FROM comments c
        LEFT JOIN users u ON c.author_id = u.id
        WHERE c.id = ?
    """, (comment_id,))
    
    updated_comment = cursor.fetchone()
    conn.commit()
    conn.close()
    
    return CommentResponse(**dict(updated_comment))

@comments_router.delete("/{comment_id}")
async def delete_comment(
    comment_id: int,
    current_user: dict = Depends(get_current_active_user)
):
    """Deletar comentário (autor ou admin)"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Verificar se o comentário existe
    cursor.execute("SELECT author_id FROM comments WHERE id = ?", (comment_id,))
    comment = cursor.fetchone()
    
    if not comment:
        conn.close()
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Comentário não encontrado"
        )
    
    # Verificar permissões (autor do comentário ou admin)
    if comment['author_id'] != current_user['id'] and current_user['role'] != 'admin':
        conn.close()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Sem permissão para deletar este comentário"
        )
    
    cursor.execute("DELETE FROM comments WHERE id = ?", (comment_id,))
    conn.commit()
    conn.close()
    
    return {"message": "Comentário deletado com sucesso"}

# Rotas de favoritos
@favorites_router.get("/")
async def get_favorites(current_user: dict = Depends(get_current_active_user)):
    """Listar artigos favoritos do usuário"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT a.*, f.created_at as addedToFavoritesAt FROM favorites f
        JOIN articles a ON a.id = f.article_id
        WHERE f.user_id = ?
        ORDER BY f.created_at DESC
    """, (current_user["id"],))
    
    articles = cursor.fetchall()
    conn.close()
    
    # Convertendo para dicionário e incluindo campo addedToFavoritesAt
    result = []
    for article in articles:
        article_dict = dict(article)
        result.append(article_dict)
    
    return result

@favorites_router.post("/{article_id}")
async def add_favorite(article_id: int, current_user: dict = Depends(get_current_active_user)):
    """Adicionar artigo aos favoritos"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Verificar se o artigo já está nos favoritos
    cursor.execute("SELECT 1 FROM favorites WHERE user_id = ? AND article_id = ?", (current_user["id"], article_id))
    if cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail="Artigo já está nos favoritos")
    
    # Adicionar favorito
    cursor.execute("INSERT INTO favorites (user_id, article_id, created_at) VALUES (?, ?, datetime('now'))", (current_user["id"], article_id))
    conn.commit()
    conn.close()
    
    return {"message": "Favorito adicionado"}

@favorites_router.delete("/{article_id}")
async def remove_favorite(article_id: int, current_user: dict = Depends(get_current_active_user)):
    """Remover artigo dos favoritos"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Remover favorito
    cursor.execute("DELETE FROM favorites WHERE user_id = ? AND article_id = ?", (current_user["id"], article_id))
    conn.commit()
    conn.close()
    
    return {"message": "Favorito removido com sucesso"}

@favorites_router.delete("/")
async def clear_all_favorites(current_user: dict = Depends(get_current_active_user)):
    """Remover todos os favoritos do usuário"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Remover todos os favoritos do usuário
    cursor.execute("DELETE FROM favorites WHERE user_id = ?", (current_user["id"],))
    rows_deleted = cursor.rowcount
    conn.commit()
    conn.close()
    
    return {"message": f"{rows_deleted} favoritos removidos com sucesso"}
    
    return {"message": "Favorito removido"}
