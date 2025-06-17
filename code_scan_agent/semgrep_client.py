"""
Semgrep MCP Client

High-performance client for interacting with Semgrep MCP server via uvx.
Implements MCP protocol specification with enterprise-grade resilience patterns.

Features:
- Asynchronous and synchronous communication modes
- Circuit breaker pattern for fault tolerance
- Comprehensive error handling and recovery
- Resource management and cleanup
- Thread-safe operations
- Health monitoring and preflight checks
"""
import asyncio
import json
import logging
import os
import subprocess
import time
import threading
from pathlib import Path
from typing import Dict, List, Any, Optional, Union
from concurrent.futures import ThreadPoolExecutor
import signal

from .errors import (
    ErrorCode, ErrorSeverity, CodeScanException, error_handler,
    CircuitBreaker, handle_errors, create_error_response
)

logger = logging.getLogger(__name__)

# Legacy exception classes cho backward compatibility
class SemgrepMCPError(CodeScanException):
    """Base exception cho Semgrep MCP operations - legacy compatibility"""
    def __init__(self, message: str, **kwargs):
        super().__init__(
            code=ErrorCode.PROTOCOL_ERROR,
            message=message,
            component="semgrep_client",
            **kwargs
        )

class SemgrepServerError(CodeScanException):
    """Exception khi server process gặp vấn đề - legacy compatibility"""
    def __init__(self, message: str, **kwargs):
        super().__init__(
            code=ErrorCode.SERVER_START_FAILED,
            message=message,
            severity=ErrorSeverity.HIGH,
            component="semgrep_client",
            **kwargs
        )

class SemgrepProtocolError(CodeScanException):
    """Exception khi giao tiếp MCP protocol bị lỗi - legacy compatibility"""
    def __init__(self, message: str, **kwargs):
        super().__init__(
            code=ErrorCode.MCP_PROTOCOL_ERROR,
            message=message,
            severity=ErrorSeverity.MEDIUM,
            component="semgrep_client",
            **kwargs
        )

class SemgrepSyncClient:
    """
    Sync wrapper cho Semgrep MCP với enhanced error handling và circuit breaker
    Tuân thủ MCP protocol specification và enterprise-grade resilience patterns
    """
    
    def __init__(self, timeout: int = 30, max_retries: int = 3):
        self.server_process = None
        self.request_id = 1
        self.initialized = False
        self.timeout = timeout
        self.max_retries = max_retries
        self._lock = threading.Lock()
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="semgrep-mcp")
        
        # Enhanced error handling components
        self.circuit_breaker = error_handler.get_circuit_breaker("semgrep_server")
        self.error_counts = {"connection_errors": 0, "timeout_errors": 0, "protocol_errors": 0}
        self.last_health_check = None
    
    @handle_errors("semgrep_client", "start_server")
    def start_server(self) -> None:
        """Khởi động Semgrep MCP server bằng uvx với enhanced error handling và circuit breaker"""
        with self._lock:
            if self.server_process and self._is_server_running():
                logger.info("Semgrep MCP server đã đang chạy")
                return
            
            def _start_server_internal():
                try:
                    # Pre-flight checks
                    self._perform_preflight_checks()
                    
                    # Kiểm tra uvx có sẵn không
                    result = subprocess.run(
                        ["uvx", "--version"], 
                        check=True, 
                        capture_output=True,
                        timeout=10
                    )
                    logger.debug(f"uvx version: {result.stdout.decode().strip()}")
                    
                    # Khởi động server với proper environment
                    env = os.environ.copy()
                    env['PYTHONUNBUFFERED'] = '1'  # Ensure unbuffered output
                    
                    self.server_process = subprocess.Popen(
                        ["uvx", "semgrep-mcp"],
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        bufsize=0,  # Unbuffered
                        env=env,
                        preexec_fn=os.setsid if hasattr(os, 'setsid') else None  # Process group for cleanup
                    )
                    logger.info("Semgrep MCP server đã được khởi động")
                    
                    # Wait for server to be ready với timeout
                    self._wait_for_server_ready()
                    
                    # Initialize MCP session
                    self.initialize()
                    
                    # Mark last successful health check
                    self.last_health_check = time.time()
                    
                except FileNotFoundError:
                    raise CodeScanException(
                        code=ErrorCode.SERVER_START_FAILED,
                        message="uvx không được tìm thấy. Vui lòng cài đặt uv và uvx.",
                        severity=ErrorSeverity.CRITICAL,
                        component="semgrep_client",
                        operation="start_server",
                        recovery_suggestion="Cài đặt uv: curl -LsSf https://astral.sh/uv/install.sh | sh"
                    )
                except subprocess.CalledProcessError as e:
                    error_detail = e.stderr.decode() if e.stderr else str(e)
                    raise CodeScanException(
                        code=ErrorCode.SERVER_START_FAILED,
                        message=f"Lỗi khi khởi động server: {error_detail}",
                        severity=ErrorSeverity.HIGH,
                        component="semgrep_client",
                        operation="start_server",
                        original_exception=e,
                        recovery_suggestion="Kiểm tra semgrep-mcp installation và dependencies"
                    )
                except subprocess.TimeoutExpired:
                    raise CodeScanException(
                        code=ErrorCode.REQUEST_TIMEOUT,
                        message="Timeout khi khởi động server",
                        severity=ErrorSeverity.HIGH,
                        component="semgrep_client",
                        operation="start_server",
                        recovery_suggestion="Tăng timeout hoặc kiểm tra system resources"
                    )
                except Exception as e:
                    self._cleanup_server()
                    raise CodeScanException(
                        code=ErrorCode.UNEXPECTED_ERROR,
                        message=f"Unexpected error khi khởi động server: {e}",
                        severity=ErrorSeverity.HIGH,
                        component="semgrep_client",
                        operation="start_server",
                        original_exception=e
                    )
            
            # Sử dụng circuit breaker
            try:
                self.circuit_breaker.call(_start_server_internal)
            except CodeScanException:
                self.error_counts["connection_errors"] += 1
                raise
    
    def _is_server_running(self) -> bool:
        """Kiểm tra xem server process còn đang chạy không"""
        return (self.server_process is not None and 
                self.server_process.poll() is None)
    
    def _perform_preflight_checks(self) -> None:
        """Thực hiện các kiểm tra trước khi khởi động server"""
        # Check system resources
        import psutil
        
        # Check available memory (cần ít nhất 100MB)
        available_memory = psutil.virtual_memory().available
        if available_memory < 100 * 1024 * 1024:  # 100MB
            raise CodeScanException(
                code=ErrorCode.RESOURCE_EXHAUSTED,
                message=f"Insufficient memory: {available_memory / 1024 / 1024:.1f}MB available",
                severity=ErrorSeverity.HIGH,
                component="semgrep_client",
                operation="preflight_check",
                recovery_suggestion="Free up system memory before starting server"
            )
        
        # Check if another semgrep process is running
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                if proc.info['name'] and 'semgrep' in proc.info['name'].lower():
                    cmdline = proc.info['cmdline']
                    if cmdline and any('mcp' in arg for arg in cmdline):
                        logger.warning(f"Another semgrep-mcp process detected: PID {proc.info['pid']}")
                        # Don't fail, just warn
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    
    def _wait_for_server_ready(self, max_wait: int = 10) -> None:
        """Chờ server sẵn sàng với exponential backoff"""
        wait_time = 0.5
        total_waited = 0
        
        while total_waited < max_wait:
            if not self._is_server_running():
                # Check server stderr for error details
                if self.server_process and self.server_process.stderr:
                    try:
                        stderr_content = self.server_process.stderr.read()
                        if stderr_content:
                            error_detail = stderr_content.strip()
                            raise CodeScanException(
                                code=ErrorCode.SERVER_CRASHED,
                                message=f"Server died during startup: {error_detail}",
                                severity=ErrorSeverity.HIGH,
                                component="semgrep_client",
                                operation="wait_for_ready"
                            )
                    except:
                        pass  # stderr reading failed, continue with generic error
                
                raise CodeScanException(
                    code=ErrorCode.SERVER_CRASHED,
                    message="Server process died after startup",
                    severity=ErrorSeverity.HIGH,
                    component="semgrep_client",
                    operation="wait_for_ready"
                )
            
            # Try a simple health check
            try:
                # Send a simple ping to see if server responds
                test_request = {
                    "jsonrpc": "2.0",
                    "id": 999,
                    "method": "ping",
                    "params": {}
                }
                
                request_json = json.dumps(test_request) + "\n"
                self.server_process.stdin.write(request_json)
                self.server_process.stdin.flush()
                
                # Try to read response with short timeout
                response = self._read_response_with_timeout_internal(timeout=2)
                if response:
                    logger.info("Server is ready and responding")
                    return
                    
            except Exception as e:
                logger.debug(f"Health check failed (attempt {total_waited:.1f}s): {e}")
            
            time.sleep(wait_time)
            total_waited += wait_time
            wait_time = min(wait_time * 1.5, 2.0)  # Exponential backoff, max 2s
        
        raise CodeScanException(
            code=ErrorCode.REQUEST_TIMEOUT,
            message=f"Server not ready after {max_wait}s",
            severity=ErrorSeverity.HIGH,
            component="semgrep_client",
            operation="wait_for_ready",
            recovery_suggestion="Increase timeout or check server logs"
        )
    
    def _read_response_with_timeout_internal(self, timeout: int = None) -> Optional[str]:
        """Internal version với configurable timeout"""
        actual_timeout = timeout or self.timeout
        
        import select
        import sys
        
        if not self._is_server_running():
            return None
        
        # For Windows compatibility, use a simple approach
        if sys.platform == 'win32':
            # On Windows, use threading approach
            import queue
            import threading
            
            result_queue = queue.Queue()
            
            def read_line():
                try:
                    line = self.server_process.stdout.readline()
                    result_queue.put(line)
                except Exception as e:
                    result_queue.put(None)
            
            thread = threading.Thread(target=read_line)
            thread.daemon = True
            thread.start()
            
            try:
                return result_queue.get(timeout=actual_timeout)
            except queue.Empty:
                return None
        else:
            # On Unix-like systems, use select
            ready, _, _ = select.select([self.server_process.stdout], [], [], actual_timeout)
            if ready:
                return self.server_process.stdout.readline()
            else:
                return None
    
    def initialize(self) -> None:
        """Initialize MCP session theo protocol specification"""
        if self.initialized:
            return
            
        if not self._is_server_running():
            raise SemgrepServerError("Server process not running")
            
        # Send initialize request theo MCP spec
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
            # Send initialize với timeout
            response = self._send_request_with_timeout(init_request)
            
            if "error" in response:
                raise SemgrepProtocolError(f"MCP Initialize Error: {response['error']}")
            
            # Send initialized notification theo MCP spec
            initialized_notification = {
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
                "params": {}
            }
            
            self._send_notification(initialized_notification)
            
            self.initialized = True
            logger.info("MCP session initialized successfully")
            
        except Exception as e:
            logger.error(f"Lỗi khi initialize MCP session: {e}")
            self._cleanup_server()
            raise SemgrepProtocolError(f"Failed to initialize: {e}")
    
    def _send_request_with_timeout(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Gửi request với timeout và error handling"""
        if not self._is_server_running():
            raise SemgrepServerError("Server process not running")
        
        try:
            request_json = json.dumps(request) + "\n"
            self.server_process.stdin.write(request_json)
            self.server_process.stdin.flush()
            
            # Đọc response với timeout
            response_line = self._read_response_with_timeout()
            if not response_line:
                raise SemgrepProtocolError("No response from server")
                
            response = json.loads(response_line)
            return response
            
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON response: {e}")
            raise SemgrepProtocolError(f"Invalid JSON response: {e}")
        except BrokenPipeError:
            logger.error("Broken pipe to server")
            self._cleanup_server()
            raise SemgrepServerError("Connection to server lost")
        except Exception as e:
            logger.error(f"Request failed: {e}")
            raise SemgrepProtocolError(f"Request failed: {e}")
    
    def _send_notification(self, notification: Dict[str, Any]) -> None:
        """Gửi notification (không cần response)"""
        if not self._is_server_running():
            raise SemgrepServerError("Server process not running")
        
        try:
            notification_json = json.dumps(notification) + "\n"
            self.server_process.stdin.write(notification_json)
            self.server_process.stdin.flush()
        except Exception as e:
            logger.error(f"Failed to send notification: {e}")
            raise SemgrepProtocolError(f"Failed to send notification: {e}")
    
    def _read_response_with_timeout(self) -> Optional[str]:
        """Đọc response từ server với timeout"""
        # Simple timeout implementation
        import select
        import sys
        
        if not self._is_server_running():
            return None
        
        # For Windows compatibility, use a simple approach
        if sys.platform == 'win32':
            # On Windows, use threading approach
            import queue
            import threading
            
            result_queue = queue.Queue()
            
            def read_line():
                try:
                    line = self.server_process.stdout.readline()
                    result_queue.put(line)
                except Exception as e:
                    result_queue.put(None)
            
            thread = threading.Thread(target=read_line)
            thread.daemon = True
            thread.start()
            
            try:
                return result_queue.get(timeout=self.timeout)
            except queue.Empty:
                logger.error("Timeout reading from server")
                return None
        else:
            # On Unix-like systems, use select
            ready, _, _ = select.select([self.server_process.stdout], [], [], self.timeout)
            if ready:
                return self.server_process.stdout.readline()
            else:
                logger.error("Timeout reading from server")
                return None
    
    def stop_server(self) -> None:
        """Dừng Semgrep MCP server với proper cleanup"""
        with self._lock:
            self._cleanup_server()
    
    def _cleanup_server(self) -> None:
        """Internal cleanup method"""
        if self.server_process:
            try:
                # Try graceful termination first
                self.server_process.terminate()
                try:
                    self.server_process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    # Force kill if graceful termination fails
                    logger.warning("Server didn't terminate gracefully, forcing kill")
                    self.server_process.kill()
                    self.server_process.wait()
            except Exception as e:
                logger.warning(f"Error during server cleanup: {e}")
            finally:
                self.server_process = None
                self.initialized = False
                logger.info("Semgrep MCP server đã được dừng")
    
    def send_mcp_request(self, method: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Gửi yêu cầu MCP đến server với retry logic
        
        Args:
            method: Tên method MCP
            params: Tham số cho method
            
        Returns:
            Kết quả từ server
        """
        for attempt in range(self.max_retries):
            try:
                if not self.server_process or not self.initialized:
                    self.start_server()
                
                # Tạo JSON-RPC request theo MCP spec
                request = {
                    "jsonrpc": "2.0",
                    "id": self.request_id,
                    "method": method,
                    "params": params
                }
                self.request_id += 1
                
                response = self._send_request_with_timeout(request)
                
                if "error" in response:
                    error_detail = response["error"]
                    logger.error(f"MCP Error: {error_detail}")
                    raise SemgrepProtocolError(f"MCP Error: {error_detail}")
                    
                return response.get("result", {})
                
            except (SemgrepServerError, SemgrepProtocolError) as e:
                logger.warning(f"Attempt {attempt + 1} failed: {e}")
                if attempt < self.max_retries - 1:
                    logger.info(f"Retrying in 2 seconds...")
                    time.sleep(2)
                    self._cleanup_server()  # Reset connection
                else:
                    logger.error(f"All {self.max_retries} attempts failed")
                    raise
            except Exception as e:
                logger.error(f"Unexpected error in send_mcp_request: {e}")
                self._cleanup_server()
                raise SemgrepMCPError(f"Unexpected error: {e}")
    
    # Tool methods với improved error handling
    def list_tools(self) -> List[Dict[str, Any]]:
        """List available tools"""
        try:
            result = self.send_mcp_request("tools/list", {})
            return result.get("tools", [])
        except Exception as e:
            logger.error(f"Failed to list tools: {e}")
            return []
    
    def scan_code_files(self, code_files: List[Dict[str, str]], config: Optional[str] = None) -> Dict[str, Any]:
        """
        Scan code files để tìm lỗ hổng bảo mật
        
        Args:
            code_files: Danh sách files với 'filename' và 'content'
            config: Cấu hình Semgrep (tùy chọn)
            
        Returns:
            Kết quả scan
        """
        if not code_files:
            return {"status": "error", "message": "No code files provided"}
        
        params = {"code_files": code_files}
        if config:
            params["config"] = config
            
        return self.send_mcp_request("tools/call", {
            "name": "semgrep_scan",
            "arguments": params
        })
    
    def scan_directory(self, directory_path: str, config: Optional[str] = None) -> Dict[str, Any]:
        """
        Scan toàn bộ thư mục với improved file discovery
        
        Args:
            directory_path: Đường dẫn thư mục cần scan
            config: Cấu hình Semgrep (tùy chọn)
            
        Returns:
            Kết quả scan
        """
        code_files = []
        directory = Path(directory_path)
        
        if not directory.exists():
            raise ValueError(f"Directory does not exist: {directory_path}")
        
        if not directory.is_dir():
            raise ValueError(f"Path is not a directory: {directory_path}")
        
        # Các extension được hỗ trợ bởi Semgrep
        supported_extensions = {
            '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.cpp', '.c', '.h',
            '.cs', '.php', '.rb', '.go', '.rs', '.swift', '.kt', '.scala',
            '.html', '.xml', '.yaml', '.yml', '.json', '.sql', '.sh', '.bash',
            '.vue', '.dart', '.lua', '.r', '.tf', '.hcl', '.sol'
        }
        
        # Exclude patterns (common build/dependency directories)
        exclude_patterns = {
            'node_modules', '.git', '__pycache__', '.pytest_cache',
            'venv', '.venv', 'env', '.env', 'build', 'dist', 'target',
            '.next', '.nuxt', 'coverage', '.coverage', '.nyc_output'
        }
        
        try:
            for file_path in directory.rglob('*'):
                # Skip if in excluded directory
                if any(part in exclude_patterns for part in file_path.parts):
                    continue
                    
                if file_path.is_file() and file_path.suffix in supported_extensions:
                    try:
                        # Skip very large files (>1MB)
                        if file_path.stat().st_size > 1024 * 1024:
                            logger.warning(f"Skipping large file: {file_path}")
                            continue
                            
                        content = file_path.read_text(encoding='utf-8', errors='ignore')
                        relative_path = file_path.relative_to(directory)
                        
                        code_files.append({
                            "filename": str(relative_path),
                            "content": content
                        })
                    except Exception as e:
                        logger.warning(f"Không thể đọc file {file_path}: {e}")
                        continue
            
            logger.info(f"Tìm thấy {len(code_files)} files để scan trong {directory_path}")
            
            if not code_files:
                return {
                    "status": "warning",
                    "message": f"No supported code files found in {directory_path}",
                    "supported_extensions": list(supported_extensions)
                }
                
            return self.scan_code_files(code_files, config)
            
        except Exception as e:
            logger.error(f"Error scanning directory {directory_path}: {e}")
            raise SemgrepMCPError(f"Directory scan failed: {e}")
    
    def scan_with_custom_rule(self, code_files: List[Dict[str, str]], rule: str) -> Dict[str, Any]:
        """Scan với custom rule"""
        if not code_files:
            return {"status": "error", "message": "No code files provided"}
        
        return self.send_mcp_request("tools/call", {
            "name": "semgrep_scan_with_custom_rule",
            "arguments": {
                "code_files": code_files,
                "rule": rule
            }
        })
    
    def security_check(self, code_files: List[Dict[str, str]]) -> Dict[str, Any]:
        """Thực hiện security check nhanh"""
        if not code_files:
            return {"status": "error", "message": "No code files provided"}
        
        return self.send_mcp_request("tools/call", {
            "name": "security_check",
            "arguments": {"code_files": code_files}
        })
    
    def get_supported_languages(self) -> List[str]:
        """Lấy danh sách ngôn ngữ được hỗ trợ"""
        try:
            result = self.send_mcp_request("tools/call", {
                "name": "get_supported_languages",
                "arguments": {}
            })
            
            # Handle different response formats
            if isinstance(result, dict):
                if "content" in result and isinstance(result["content"], list):
                    return result["content"]
                elif isinstance(result.get("result"), list):
                    return result["result"]
            
            logger.warning(f"Unexpected response format for supported languages: {result}")
            return []
            
        except Exception as e:
            logger.error(f"Failed to get supported languages: {e}")
            return []
    
    def get_abstract_syntax_tree(self, code: str, language: str) -> Dict[str, Any]:
        """Lấy Abstract Syntax Tree của code"""
        if not code or not language:
            return {"status": "error", "message": "Code and language are required"}
        
        return self.send_mcp_request("tools/call", {
            "name": "get_abstract_syntax_tree",
            "arguments": {
                "code": code,
                "language": language
            }
        })
    
    def get_rule_schema(self) -> Dict[str, Any]:
        """Lấy schema cho Semgrep rules"""
        try:
            return self.send_mcp_request("tools/call", {
                "name": "semgrep_rule_schema",
                "arguments": {}
            })
        except Exception as e:
            logger.error(f"Failed to get rule schema: {e}")
            return {"status": "error", "message": str(e)}
    
    def __enter__(self):
        """Context manager support"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager cleanup"""
        self.stop_server()
    
    def __del__(self):
        """Cleanup khi object bị hủy"""
        try:
            self.stop_server()
            if hasattr(self, '_executor'):
                self._executor.shutdown(wait=False)
        except Exception:
            pass  # Ignore errors during cleanup


class SemgrepAsyncClient:
    """
    Async wrapper cho SemgrepSyncClient
    Sử dụng ThreadPoolExecutor để chạy sync operations trong background
    """
    
    def __init__(self, timeout: int = 30, max_retries: int = 3):
        self._sync_client = SemgrepSyncClient(timeout=timeout, max_retries=max_retries)
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="semgrep-async")
    
    async def start_server(self) -> None:
        """Async wrapper for start_server"""
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(self._executor, self._sync_client.start_server)
    
    async def stop_server(self) -> None:
        """Async wrapper for stop_server"""
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(self._executor, self._sync_client.stop_server)
    
    async def list_tools(self) -> List[Dict[str, Any]]:
        """Async wrapper for list_tools"""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(self._executor, self._sync_client.list_tools)
    
    async def scan_code_files(self, code_files: List[Dict[str, str]], config: Optional[str] = None) -> Dict[str, Any]:
        """Async wrapper for scan_code_files"""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            self._executor, 
            self._sync_client.scan_code_files, 
            code_files, 
            config
        )
    
    async def scan_directory(self, directory_path: str, config: Optional[str] = None) -> Dict[str, Any]:
        """Async wrapper for scan_directory"""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            self._executor,
            self._sync_client.scan_directory,
            directory_path,
            config
        )
    
    async def security_check(self, code_files: List[Dict[str, str]]) -> Dict[str, Any]:
        """Async wrapper for security_check"""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            self._executor,
            self._sync_client.security_check,
            code_files
        )
    
    async def get_supported_languages(self) -> List[str]:
        """Async wrapper for get_supported_languages"""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(self._executor, self._sync_client.get_supported_languages)
    
    async def __aenter__(self):
        """Async context manager support"""
        await self.start_server()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager cleanup"""
        await self.stop_server()
        self._executor.shutdown(wait=False)


# Keep backward compatibility
class SemgrepMCPClient(SemgrepSyncClient):
    """Alias for backward compatibility - defaults to sync client"""
    pass 