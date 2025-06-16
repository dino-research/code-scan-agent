"""
Configuration module cho Code Scan Agent
"""
import os
from pathlib import Path
from typing import Optional


class Config:
    """Lớp quản lý cấu hình cho agent"""
    
    def __init__(self):
        """Khởi tạo cấu hình từ environment variables"""
        # Load .env file nếu có
        self._load_dotenv()
        
        # ADK Configuration
        self.google_genai_use_vertexai = os.getenv("GOOGLE_GENAI_USE_VERTEXAI", "FALSE").upper() == "TRUE"
        self.google_api_key = os.getenv("GOOGLE_API_KEY")
        self.google_cloud_project = os.getenv("GOOGLE_CLOUD_PROJECT")
        self.google_cloud_location = os.getenv("GOOGLE_CLOUD_LOCATION", "us-central1")
        
        # Logging
        self.log_level = os.getenv("LOG_LEVEL", "INFO")
        
    def _load_dotenv(self):
        """Load .env file nếu có"""
        try:
            from dotenv import load_dotenv
            env_file = Path(__file__).parent / ".env"
            if env_file.exists():
                load_dotenv(env_file)
        except ImportError:
            # python-dotenv không có sẵn
            pass
    
    def validate(self) -> bool:
        """
        Kiểm tra cấu hình có hợp lệ không
        
        Returns:
            bool: True nếu cấu hình hợp lệ
        """
        if self.google_genai_use_vertexai:
            # Vertex AI mode
            if not self.google_cloud_project:
                print("❌ Lỗi: GOOGLE_CLOUD_PROJECT không được thiết lập")
                return False
        else:
            # Google AI Studio mode
            if not self.google_api_key:
                print("❌ Lỗi: GOOGLE_API_KEY không được thiết lập")
                return False
        
        return True
    
    def print_config(self):
        """In ra cấu hình hiện tại (ẩn thông tin nhạy cảm)"""
        print("🔧 Cấu hình Code Scan Agent:")
        print(f"   • ADK Mode: {'Vertex AI' if self.google_genai_use_vertexai else 'Google AI Studio'}")
        
        if self.google_genai_use_vertexai:
            print(f"   • Project: {self.google_cloud_project}")
            print(f"   • Location: {self.google_cloud_location}")
        else:
            api_key_display = f"{self.google_api_key[:8]}..." if self.google_api_key else "Chưa thiết lập"
            print(f"   • API Key: {api_key_display}")
        
        print(f"   • Log Level: {self.log_level}")
    
    def setup_instructions(self):
        """In hướng dẫn thiết lập cấu hình"""
        print("\n📋 Hướng dẫn thiết lập:")
        print("\n1. Tạo file .env trong thư mục code_scan_agent:")
        print("   cp code_scan_agent/config.py code_scan_agent/.env")
        
        print("\n2. Thiết lập authentication cho ADK:")
        print("   Phương thức A - Google AI Studio (dễ hơn):")
        print("   • Lấy API key từ: https://aistudio.google.com/app/apikey")
        print("   • Thêm vào .env: GOOGLE_API_KEY=your_api_key_here")
        print("   • Thêm vào .env: GOOGLE_GENAI_USE_VERTEXAI=FALSE")
        
        print("\n   Phương thức B - Google Cloud Vertex AI:")
        print("   • Thiết lập gcloud CLI và authenticate")
        print("   • Thêm vào .env: GOOGLE_CLOUD_PROJECT=your_project_id")
        print("   • Thêm vào .env: GOOGLE_GENAI_USE_VERTEXAI=TRUE")
        
        print("\n3. Cài đặt dependencies:")
        print("   uv install")


# Global config instance
config = Config()


def get_config() -> Config:
    """Lấy instance cấu hình global"""
    return config 