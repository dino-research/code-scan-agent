"""
Semgrep MCP Client
Client để tương tác với Semgrep MCP server thông qua uvx
"""
import asyncio
import json
import logging
import os
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)


class SemgrepSyncClient:
    """Sync wrapper cho Semgrep MCP để tránh asyncio conflicts"""
    
    def __init__(self):
        self.server_process = None
        self.request_id = 1
        self.initialized = False
    
    def start_server(self) -> None:
        """Khởi động Semgrep MCP server bằng uvx"""
        try:
            # Kiểm tra xem uvx có sẵn không
            subprocess.run(["uvx", "--version"], check=True, capture_output=True)
            
            # Khởi động server
            self.server_process = subprocess.Popen(
                ["uvx", "semgrep-mcp"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            logger.info("Semgrep MCP server đã được khởi động")
            
            # Wait a bit for server to start
            time.sleep(2)
            
            # Initialize MCP session
            self.initialize()
            
        except FileNotFoundError:
            logger.error("uvx không được tìm thấy. Vui lòng cài đặt uv và uvx.")
            raise
        except subprocess.CalledProcessError as e:
            logger.error(f"Lỗi khi khởi động server: {e}")
            raise
    
    def initialize(self) -> None:
        """Initialize MCP session"""
        if self.initialized:
            return
            
        # Send initialize request
        init_request = {
            "jsonrpc": "2.0",
            "id": self.request_id,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {}
                },
                "clientInfo": {
                    "name": "code-scan-agent",
                    "version": "1.0.0"
                }
            }
        }
        self.request_id += 1
        
        try:
            # Send initialize
            request_json = json.dumps(init_request) + "\n"
            self.server_process.stdin.write(request_json)
            self.server_process.stdin.flush()
            
            # Read response
            response_line = self.server_process.stdout.readline()
            init_response = json.loads(response_line)
            
            if "error" in init_response:
                raise Exception(f"MCP Initialize Error: {init_response['error']}")
            
            # Send initialized notification
            initialized_notification = {
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
                "params": {}
            }
            
            notification_json = json.dumps(initialized_notification) + "\n"
            self.server_process.stdin.write(notification_json)
            self.server_process.stdin.flush()
            
            self.initialized = True
            logger.info("MCP session initialized successfully")
            
        except Exception as e:
            logger.error(f"Lỗi khi initialize MCP session: {e}")
            raise
    
    def stop_server(self) -> None:
        """Dừng Semgrep MCP server"""
        if self.server_process:
            try:
                self.server_process.terminate()
                self.server_process.wait(timeout=5)
            except:
                self.server_process.kill()
            self.server_process = None
            self.initialized = False
            logger.info("Semgrep MCP server đã được dừng")
    
    def send_mcp_request(self, method: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Gửi yêu cầu MCP đến server
        
        Args:
            method: Tên method MCP
            params: Tham số cho method
            
        Returns:
            Kết quả từ server
        """
        if not self.server_process or not self.initialized:
            self.start_server()
        
        # Tạo JSON-RPC request
        request = {
            "jsonrpc": "2.0",
            "id": self.request_id,
            "method": method,
            "params": params
        }
        self.request_id += 1
        
        try:
            # Gửi request
            request_json = json.dumps(request) + "\n"
            self.server_process.stdin.write(request_json)
            self.server_process.stdin.flush()
            
            # Đọc response
            response_line = self.server_process.stdout.readline()
            if not response_line:
                raise Exception("MCP server connection lost")
                
            response = json.loads(response_line)
            
            if "error" in response:
                raise Exception(f"MCP Error: {response['error']}")
                
            return response.get("result", {})
            
        except Exception as e:
            logger.error(f"Lỗi khi gửi MCP request: {e}")
            # Reset server connection on error
            self.stop_server()
            raise
    
    def list_tools(self) -> List[Dict[str, Any]]:
        """List available tools"""
        result = self.send_mcp_request("tools/list", {})
        return result.get("tools", [])
    
    def scan_code_files(self, code_files: List[Dict[str, str]], config: Optional[str] = None) -> Dict[str, Any]:
        """
        Scan code files để tìm lỗ hổng bảo mật
        
        Args:
            code_files: Danh sách files với 'filename' và 'content'
            config: Cấu hình Semgrep (tùy chọn)
            
        Returns:
            Kết quả scan
        """
        params = {"code_files": code_files}
        if config:
            params["config"] = config
            
        return self.send_mcp_request("tools/call", {
            "name": "semgrep_scan",
            "arguments": params
        })
    
    def scan_directory(self, directory_path: str, config: Optional[str] = None) -> Dict[str, Any]:
        """
        Scan toàn bộ thư mục
        
        Args:
            directory_path: Đường dẫn thư mục cần scan
            config: Cấu hình Semgrep (tùy chọn)
            
        Returns:
            Kết quả scan
        """
        code_files = []
        directory = Path(directory_path)
        
        # Các extension được hỗ trợ
        supported_extensions = {
            '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.cpp', '.c', '.h',
            '.cs', '.php', '.rb', '.go', '.rs', '.swift', '.kt', '.scala',
            '.html', '.xml', '.yaml', '.yml', '.json', '.sql'
        }
        
        for file_path in directory.rglob('*'):
            if file_path.is_file() and file_path.suffix in supported_extensions:
                try:
                    content = file_path.read_text(encoding='utf-8', errors='ignore')
                    code_files.append({
                        "filename": str(file_path.relative_to(directory)),
                        "content": content
                    })
                except Exception as e:
                    logger.warning(f"Không thể đọc file {file_path}: {e}")
        
        logger.info(f"Tìm thấy {len(code_files)} files để scan trong {directory_path}")
        return self.scan_code_files(code_files, config)
    
    def scan_with_custom_rule(self, code_files: List[Dict[str, str]], rule: str) -> Dict[str, Any]:
        """
        Scan với custom rule
        
        Args:
            code_files: Danh sách files với 'filename' và 'content'
            rule: Custom Semgrep rule
            
        Returns:
            Kết quả scan
        """
        return self.send_mcp_request("tools/call", {
            "name": "semgrep_scan_with_custom_rule",
            "arguments": {
                "code_files": code_files,
                "rule": rule
            }
        })
    
    def security_check(self, code_files: List[Dict[str, str]]) -> Dict[str, Any]:
        """
        Thực hiện security check nhanh
        
        Args:
            code_files: Danh sách files với 'filename' và 'content'
            
        Returns:
            Kết quả security check
        """
        return self.send_mcp_request("tools/call", {
            "name": "security_check",
            "arguments": {"code_files": code_files}
        })
    
    def get_supported_languages(self) -> List[str]:
        """
        Lấy danh sách ngôn ngữ được hỗ trợ
        
        Returns:
            Danh sách ngôn ngữ
        """
        result = self.send_mcp_request("tools/call", {
            "name": "get_supported_languages",
            "arguments": {}
        })
        return result.get("content", []) if isinstance(result.get("content"), list) else []
    
    def get_abstract_syntax_tree(self, code: str, language: str) -> Dict[str, Any]:
        """
        Lấy Abstract Syntax Tree của code
        
        Args:
            code: Source code
            language: Ngôn ngữ lập trình
            
        Returns:
            AST của code
        """
        return self.send_mcp_request("tools/call", {
            "name": "get_abstract_syntax_tree",
            "arguments": {
                "code": code,
                "language": language
            }
        })
    
    def __del__(self):
        """Cleanup khi object bị hủy"""
        try:
            self.stop_server()
        except:
            pass


# Keep the old async class for backward compatibility
class SemgrepMCPClient(SemgrepSyncClient):
    """Alias for backward compatibility"""
    pass 