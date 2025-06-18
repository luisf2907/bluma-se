from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import uvicorn
from database import init_database
from routes import router, admin_router, articles_router, comments_router, favorites_router

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    print("🚀 Iniciando Bluma News Backend...")
    init_database()
    print("✅ Backend iniciado com sucesso!")
    yield
    # Shutdown
    print("🛑 Encerrando Bluma News Backend...")

app = FastAPI(
    title="Bluma News API",
    description="API para o sistema de notícias Bluma News com autenticação e gerenciamento de usuários",
    version="1.0.0",
    lifespan=lifespan
)

# Configurar CORS para permitir requisições do frontend React
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000", "http://localhost:3001", "http://localhost:3002", "https://admirable-moxie-57f00e.netlify.app", "https://bluma-se.com.br", "http://bluma-se.com.br"],  # Frontend React
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Incluir rotas
app.include_router(router)
app.include_router(admin_router)
app.include_router(articles_router)
app.include_router(comments_router)
app.include_router(favorites_router)

@app.get("/")
async def root():
    """Endpoint raiz da API"""
    return {
        "message": "🌸 Bem-vindo à API do Bluma News!",
        "version": "1.0.0",
        "docs": "/docs",
        "status": "🟢 Online"
    }

@app.get("/api/health")
async def health_check():
    """Verificação de saúde da API"""
    return {
        "status": "healthy",
        "message": "🌿 API funcionando perfeitamente!"
    }

if __name__ == "__main__":
    print("🌸 Iniciando servidor Bluma News Backend...")
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
