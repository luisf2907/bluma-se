#!/bin/bash

echo "🌸 Configurando Bluma News Backend..."

# Verificar se o Python está instalado
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 não encontrado. Por favor, instale o Python 3."
    exit 1
fi

# Criar ambiente virtual se não existir
if [ ! -d "venv" ]; then
    echo "📦 Criando ambiente virtual..."
    python3 -m venv venv
fi

# Ativar ambiente virtual
echo "🔌 Ativando ambiente virtual..."
source venv/bin/activate

# Instalar dependências
echo "📥 Instalando dependências..."
pip install -r requirements.txt

echo "✅ Configuração concluída!"
echo ""
echo "Para iniciar o servidor:"
echo "1. Ative o ambiente virtual: source venv/bin/activate"
echo "2. Execute: python main.py"
echo ""
echo "Ou execute: ./start_server.sh"
