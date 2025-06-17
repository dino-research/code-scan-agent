"""
Configuration Management

Module quản lý cấu hình tập trung cho Code Scan Agent.
Hỗ trợ cấu hình qua file .env, environment variables và config file.
"""

import os
import logging
from typing import Dict, Any, Optional
from pathlib import Path

# Cấu hình logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Default configuration
DEFAULT_CONFIG = {
    # Semgrep client configuration
    "SEMGREP_TIMEOUT": 30,
    "SEMGREP_MAX_RETRIES": 3,
    "SEMGREP_DEFAULT_RULES": "auto",
    
    # Scanning limits
    "MAX_FILE_SIZE_MB": 10,
    "MAX_SCAN_TIMEOUT": 300,
    "MAX_CONCURRENT_SCANS": 4,
    
    # Intelligent scanning
    "INTELLIGENT_SCANNING_ENABLED": True,
    "INTELLIGENT_PRIORITY_THRESHOLD": "medium",
    "INTELLIGENT_MAX_SAMPLE_FILES": 20,
    
    # Feature flags
    "ENABLE_CIRCUIT_BREAKER": True,
    "DETAILED_ERROR_REPORTING": True,
    "ENABLE_PERFORMANCE_MONITORING": True,
    
    # Paths
    "TEMP_DIR": "/tmp/code_scan_agent",
}


class ConfigManager:
    """
    Quản lý cấu hình tập trung cho Code Scan Agent.
    Cung cấp interface thống nhất để truy cập cấu hình từ các module khác.
    """
    
    _instance = None
    _config = {}
    
    def __new__(cls, *args, **kwargs):
        """Singleton pattern để đảm bảo chỉ có một instance của ConfigManager"""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self, config_file: Optional[str] = None):
        """
        Khởi tạo ConfigManager với config từ file và environment
        
        Args:
            config_file: Đường dẫn đến file cấu hình (optional)
        """
        if self._initialized:
            return
            
        # Load default config
        self._config = DEFAULT_CONFIG.copy()
        
        # Load from environment variables
        self._load_from_env()
        
        # Load từ .env file nếu có
        self._load_dotenv()
        
        # Load từ config file nếu có
        if config_file:
            self._load_from_file(config_file)
            
        self._initialized = True
        logger.debug("ConfigManager initialized")
    
    def _load_from_env(self):
        """Load cấu hình từ environment variables"""
        for key in DEFAULT_CONFIG:
            env_value = os.environ.get(key)
            if env_value is not None:
                # Convert từ string sang đúng kiểu dữ liệu
                default_value = DEFAULT_CONFIG[key]
                if isinstance(default_value, bool):
                    self._config[key] = env_value.lower() in ('true', '1', 'yes')
                elif isinstance(default_value, int):
                    self._config[key] = int(env_value)
                elif isinstance(default_value, float):
                    self._config[key] = float(env_value)
                else:
                    self._config[key] = env_value
    
    def _load_dotenv(self):
        """Load cấu hình từ file .env nếu có"""
        try:
            from dotenv import load_dotenv
            env_path = Path(__file__).parent / '.env'
            if env_path.exists():
                load_dotenv(dotenv_path=env_path)
                # Reload từ env sau khi load .env
                self._load_from_env()
                logger.debug(f"Loaded configuration from {env_path}")
        except ImportError:
            logger.debug("python-dotenv not installed, skipping .env file")
    
    def _load_from_file(self, config_file: str):
        """Load cấu hình từ file (JSON or YAML)"""
        config_path = Path(config_file)
        if not config_path.exists():
            logger.warning(f"Config file not found: {config_file}")
            return
            
        try:
            if config_path.suffix.lower() == '.json':
                import json
                with open(config_path, 'r') as f:
                    file_config = json.load(f)
                    self._config.update(file_config)
                    logger.debug(f"Loaded JSON config from {config_file}")
                    
            elif config_path.suffix.lower() in ('.yaml', '.yml'):
                try:
                    import yaml
                    with open(config_path, 'r') as f:
                        file_config = yaml.safe_load(f)
                        if file_config:
                            self._config.update(file_config)
                            logger.debug(f"Loaded YAML config from {config_file}")
                except ImportError:
                    logger.warning("PyYAML not installed, cannot load YAML config")
            else:
                logger.warning(f"Unsupported config file format: {config_path.suffix}")
        except Exception as e:
            logger.error(f"Error loading config from file {config_file}: {e}")
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get giá trị cấu hình theo key
        
        Args:
            key: Tên của cấu hình cần lấy
            default: Giá trị mặc định nếu key không tồn tại
            
        Returns:
            Giá trị cấu hình hoặc default value
        """
        return self._config.get(key, default)
    
    def set(self, key: str, value: Any) -> None:
        """
        Set giá trị cấu hình runtime
        
        Args:
            key: Tên của cấu hình cần set
            value: Giá trị mới
        """
        self._config[key] = value
        logger.debug(f"Set config {key}={value}")
    
    def get_all(self) -> Dict[str, Any]:
        """
        Get tất cả cấu hình hiện tại
        
        Returns:
            Dict chứa tất cả cấu hình
        """
        return self._config.copy()
    
    def print_config(self) -> None:
        """
        In ra tất cả cấu hình hiện tại
        Hữu ích cho debugging và testing
        """
        print("\n📋 Current Configuration:")
        print("-" * 40)
        for key, value in sorted(self._config.items()):
            print(f"   • {key}: {value}")
        print("-" * 40)
    
    def validate(self) -> bool:
        """
        Kiểm tra tính hợp lệ của cấu hình
        
        Returns:
            True nếu cấu hình hợp lệ, False nếu không
        """
        # Kiểm tra các giá trị bắt buộc
        required_keys = [
            "SEMGREP_TIMEOUT", 
            "SEMGREP_DEFAULT_RULES",
            "MAX_FILE_SIZE_MB"
        ]
        
        for key in required_keys:
            if key not in self._config:
                logger.error(f"Missing required config: {key}")
                return False
        
        # Kiểm tra giá trị hợp lệ
        if self._config.get("SEMGREP_TIMEOUT", 0) <= 0:
            logger.error("SEMGREP_TIMEOUT must be positive")
            return False
            
        if self._config.get("MAX_FILE_SIZE_MB", 0) <= 0:
            logger.error("MAX_FILE_SIZE_MB must be positive")
            return False
        
        return True


# Global instance for easy import
config = ConfigManager()


def get_config() -> ConfigManager:
    """Lấy instance cấu hình global"""
    return config 