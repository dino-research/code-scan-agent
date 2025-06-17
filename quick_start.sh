#!/bin/bash

# Code Scan Agent - Quick Start Script
# Thiết lập và chạy agent scan code

set -e

echo "🚀 Code Scan Agent - Quick Start"
echo "================================="

# Check if uv is installed
if ! command -v uv &> /dev/null; then
    echo "📦 Installing uv package manager..."
    curl -LsSf https://astral.sh/uv/install.sh | sh
    source ~/.bashrc || source ~/.zshrc || true
    export PATH="$HOME/.cargo/bin:$PATH"
fi

echo "✅ uv is available"

# Run setup
echo "🔧 Running setup..."
python setup.py

# Check if .env file exists and has API key
ENV_FILE="code_scan_agent/.env"
if [ -f "$ENV_FILE" ]; then
    if grep -q "YOUR_GOOGLE_AI_STUDIO_API_KEY_HERE" "$ENV_FILE"; then
        echo ""
        echo "⚠️  CONFIGURATION REQUIRED"
        echo "Please edit $ENV_FILE and:"
        echo "1. Replace YOUR_GOOGLE_AI_STUDIO_API_KEY_HERE with your actual API key"
        echo "2. Get API key from: https://aistudio.google.com/app/apikey"
        echo ""
        echo "After configuration, run:"
        echo "  python test_agent.py    # Test the agent"
        echo "  adk web                 # Run Web UI"
        echo ""
        exit 1
    fi
fi

# Run tests
echo "🧪 Running tests..."
python test_agent.py

if [ $? -eq 0 ]; then
    echo ""
    echo "🎉 Setup complete! Choose how to run the agent:"
    echo ""
    echo "1. Web UI (Recommended):"
    echo "   adk web"
    echo "   Then open: http://localhost:8000"
    echo ""
    echo "2. Terminal:"
    echo "   adk run code_scan_agent"
    echo ""
    echo "3. API Server:"
    echo "   adk api_server"
    echo ""
else
    echo ""
    echo "❌ Setup failed. Please check the configuration and try again."
    exit 1
fi

echo "🚀 Starting Code Scan Agent Web UI..."

# Activate virtual environment if exists
if [ -d "venv" ]; then
    echo "📦 Activating virtual environment..."
    source venv/bin/activate
else
    echo "⚠️  Virtual environment not found! Creating one..."
    python3 -m venv venv
    source venv/bin/activate
    echo "📦 Installing dependencies..."
    pip install -e .
fi

# Start ADK web interface
echo "🌐 Starting ADK web interface..."
echo "📝 Agent sẽ có thể scan thư mục sau khi khởi động thành công"
echo ""
adk web

echo "👋 Web UI stopped. Goodbye!" 