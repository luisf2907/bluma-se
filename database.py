import sqlite3
import os
from datetime import datetime
from passlib.context import CryptContext

# Configuração para hash de senhas
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

DATABASE_FILE = "bluma_news.db"

def get_db_connection():
    """Retorna uma conexão com o banco de dados SQLite"""
    conn = sqlite3.connect(DATABASE_FILE)
    conn.row_factory = sqlite3.Row  # Para retornar resultados como dicionários
    return conn

def init_database():
    """Inicializa o banco de dados criando as tabelas necessárias"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Tabela de usuários
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name VARCHAR(100) NOT NULL,
            email VARCHAR(100) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            role VARCHAR(20) DEFAULT 'user',
            avatar VARCHAR(10) DEFAULT '👤',
            is_active BOOLEAN DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Tabela de sessões/tokens
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token VARCHAR(255) NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    ''')
    
    # Tabela de notícias (para futuras funcionalidades)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS articles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title VARCHAR(255) NOT NULL,
            summary TEXT,
            content TEXT,
            image_url VARCHAR(255),
            category VARCHAR(50),
            author_id INTEGER,
            is_published BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (author_id) REFERENCES users (id)
        )
    ''')
    
    # Tabela de comentários
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            content TEXT NOT NULL,
            article_id INTEGER NOT NULL,
            author_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (article_id) REFERENCES articles (id) ON DELETE CASCADE,
            FOREIGN KEY (author_id) REFERENCES users (id) ON DELETE CASCADE
        )
    ''')
    
    # Tabela de favoritos
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS favorites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            article_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(user_id, article_id),
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
            FOREIGN KEY (article_id) REFERENCES articles (id) ON DELETE CASCADE
        )
    ''')
    
    conn.commit()
    
    # Criar usuário admin padrão se não existir
    cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'")
    admin_count = cursor.fetchone()[0]
    
    if admin_count == 0:
        admin_password = pwd_context.hash("admin123")
        cursor.execute('''
            INSERT INTO users (name, email, password_hash, role, avatar)
            VALUES (?, ?, ?, ?, ?)
        ''', ("Administrador", "admin@bluma.com", admin_password, "admin", "👑"))
        
        # Criar alguns usuários de teste
        demo_users = [
            ("Demo User", "demo@bluma.com", pwd_context.hash("123456"), "user", "🌸"),
            ("Maria Silva", "maria@bluma.com", pwd_context.hash("senha123"), "editor", "🌺"),
            ("João Santos", "joao@bluma.com", pwd_context.hash("minhasenha"), "user", "🌿")
        ]
        
        cursor.executemany('''
            INSERT INTO users (name, email, password_hash, role, avatar)
            VALUES (?, ?, ?, ?, ?)
        ''', demo_users)
        
        conn.commit()
        print("✅ Usuários de demonstração criados:")
        print("🔑 Admin: admin@bluma.com / admin123")
        print("👤 Demo: demo@bluma.com / 123456")
        print("📝 Editor: maria@bluma.com / senha123")
        print("👤 User: joao@bluma.com / minhasenha")
    
    conn.close()

def hash_password(password: str) -> str:
    """Gera hash da senha"""
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifica se a senha está correta"""
    return pwd_context.verify(plain_password, hashed_password)

if __name__ == "__main__":
    init_database()
    print("🗄️ Banco de dados inicializado com sucesso!")
