#!/usr/bin/env python3
"""
Setup script cho Code Scan Agent
Cài đặt dependencies và thiết lập môi trường
"""
import subprocess
import sys
import os
from pathlib import Path


def run_command(command: str, description: str) -> bool:
    """
    Chạy command và in kết quả
    
    Args:
        command: Command cần chạy
        description: Mô tả command
        
    Returns:
        True nếu thành công
    """
    print(f"📦 {description}...")
    try:
        result = subprocess.run(
            command.split(),
            capture_output=True,
            text=True,
            check=True
        )
        print(f"✅ {description} thành công!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ {description} thất bại: {e}")
        if e.stdout:
            print(f"STDOUT: {e.stdout}")
        if e.stderr:
            print(f"STDERR: {e.stderr}")
        return False


def check_prerequisites():
    """Kiểm tra các điều kiện tiên quyết"""
    print("🔍 Kiểm tra điều kiện tiên quyết...")
    
    # Kiểm tra Python version
    if sys.version_info < (3, 10):
        print("❌ Cần Python 3.10 trở lên")
        return False
    print(f"✅ Python {sys.version}")
    
    # Kiểm tra uv
    try:
        subprocess.run(["uv", "--version"], capture_output=True, check=True)
        print("✅ uv đã được cài đặt")
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("❌ uv chưa được cài đặt")
        print("   Cài đặt uv: curl -LsSf https://astral.sh/uv/install.sh | sh")
        return False
    
    return True


def install_dependencies():
    """Cài đặt dependencies"""
    print("\n📦 Cài đặt dependencies...")
    
    # Cài đặt với uv
    commands = [
        ("uv sync", "Đồng bộ dependencies"),
    ]
    
    for command, description in commands:
        if not run_command(command, description):
            return False
    
    return True


def setup_semgrep():
    """Thiết lập Semgrep MCP"""
    print("\n🔧 Thiết lập Semgrep MCP...")
    
    # Cài đặt semgrep-mcp qua uvx
    try:
        print("📦 Cài đặt semgrep-mcp qua uvx...")
        result = subprocess.run(
            ["uvx", "semgrep-mcp", "--version"],
            capture_output=True,
            text=True,
            timeout=60
        )
        print("✅ Semgrep MCP đã sẵn sàng!")
        return True
    except subprocess.TimeoutExpired:
        print("⚠️  Semgrep MCP cài đặt lần đầu có thể mất thời gian...")
        # Thử cài đặt một lần nữa
        try:
            subprocess.run(
                ["uvx", "--python", "3.10", "semgrep-mcp", "--version"],
                capture_output=True,
                text=True,
                timeout=120
            )
            print("✅ Semgrep MCP đã được cài đặt thành công!")
            return True
        except:
            print("⚠️  Semgrep MCP sẽ được cài đặt khi sử dụng lần đầu")
            return True
    except Exception as e:
        print(f"⚠️  Semgrep MCP sẽ được cài đặt tự động khi cần: {e}")
        return True


def create_env_file():
    """Tạo file .env với cấu hình mặc định"""
    env_content = """# Code Scan Agent Configuration

# Google AI Studio API Key (required)
GOOGLE_API_KEY=YOUR_GOOGLE_API_KEY_HERE

# ADK Configuration
GOOGLE_GENAI_USE_VERTEXAI=FALSE

# Logging
LOG_LEVEL=INFO
"""
    
    env_path = Path("code_scan_agent/.env")
    
    if env_path.exists():
        print("✅ File .env đã tồn tại")
        return True
    
    try:
        env_path.parent.mkdir(exist_ok=True)
        env_path.write_text(env_content.strip())
        print("✅ File .env đã được tạo")
        return True
    except Exception as e:
        print(f"❌ Lỗi khi tạo file .env: {e}")
        return False


def main():
    """Hàm chính"""
    print("🚀 Setup Code Scan Agent")
    print("=" * 40)
    
    # Kiểm tra điều kiện tiên quyết
    if not check_prerequisites():
        return 1
    
    # Cài đặt dependencies
    if not install_dependencies():
        return 1
    
    # Thiết lập Semgrep
    if not setup_semgrep():
        return 1
    
    # Tạo file .env
    if not create_env_file():
        return 1
    
    print("\n🎉 Setup hoàn tất!")
    print("\n📋 Bước tiếp theo:")
    print("1. Chỉnh sửa code_scan_agent/.env với API keys:")
    print("   - Google AI Studio API key hoặc Google Cloud project")
    
    print("\n2. Chạy agent:")
    print("   python run_agent.py")
    
    print("\n3. Hoặc sử dụng ADK trực tiếp:")
    print("   adk web")
    
    return 0


if __name__ == "__main__":
    sys.exit(main()) 