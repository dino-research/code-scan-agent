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
            code=ErrorCode.PROTOCOL_ERROR,
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
        """
        Khởi tạo Semgrep MCP Client với realistic timeout
        
        Args:
            timeout: Timeout cho operations (seconds) - 30s là đủ cho MCP
            max_retries: Số lần thử lại tối đa
        """
        self.server_process = None
        self.initialized = False
        self.timeout = timeout
        self.max_retries = max_retries
        self.request_id = 1
        self._lock = threading.Lock()
        
        # Enhanced error tracking
        self.error_counts = {
            "timeout_errors": 0,
            "connection_errors": 0,
            "json_errors": 0
        }
        self.last_health_check = 0
        
        # Circuit breaker pattern để tránh overload
        self.circuit_breaker = CircuitBreaker(
            failure_threshold=5,
            reset_timeout=300  # 5 phút
        )
    
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
                        bufsize=0,  # Unbuffered để response ngay lập tức  
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
    
    def _wait_for_server_ready(self, max_wait: int = 3) -> None:
        """Chờ server sẵn sàng với exponential backoff - giảm thời gian vì chỉ check process"""
        wait_time = 0.2
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
            
            # Simple health check - just check if server is alive, NO MCP communication yet
            try:
                # Simple check: server process is alive and responding to basic I/O
                if self.server_process.poll() is None:
                    # Server is alive, assume it's ready
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
        """Simplified direct read - như raw test"""
        actual_timeout = timeout or self.timeout
        
        if not self._is_server_running():
            return None
        
        # Simple direct approach như raw test - hoạt động ngay lập tức
        import select
        import sys
        
        try:
            start_time = time.time()
            
            # Poll approach như raw test
            while time.time() - start_time < actual_timeout:
                # Check if server died
                if self.server_process.poll() is not None:
                    logger.error(f"Server died with exit code: {self.server_process.poll()}")
                    return None
                
                # Try to read
                if sys.platform != 'win32':
                    ready, _, _ = select.select([self.server_process.stdout], [], [], 0.1)
                    if ready:
                        line = self.server_process.stdout.readline()
                        if line and line.strip():
                            return line.strip()
                else:
                    # Windows approach - improved
                    try:
                        line = self.server_process.stdout.readline()
                        if line and line.strip():
                            return line.strip()
                    except:
                        pass
                
                time.sleep(0.01)  # Short sleep để không busy wait
            
            logger.error(f"Timeout reading response after {actual_timeout}s")
            return None
            
        except Exception as e:
            logger.error(f"Error reading response: {e}")
            return None
    def initialize(self) -> None:
        """Initialize MCP session - rewritten với raw approach thành công"""
        if self.initialized:
            return

        if not self._is_server_running():
            raise SemgrepServerError("Server không đang chạy")

        try:
            # Initialize request
            initialize_request = {
                "jsonrpc": "2.0",
                "id": self.request_id,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {
                        "roots": {
                            "listChanged": True
                        },
                        "sampling": {}
                    },
                    "clientInfo": {
                        "name": "code-scan-agent",
                        "version": "1.0.0"
                    }
                }
            }
            self.request_id += 1

            # EXACT COPY of working test approach
            import select
            import sys
            
            request_json = json.dumps(initialize_request) + "\n"
            logger.debug(f"Sending initialize: {request_json.strip()}")
            
            # Send request - exact same as working test
            self.server_process.stdin.write(request_json)
            self.server_process.stdin.flush()
            
            # Read response - EXACT COPY of working approach
            response_line = None
            start_time = time.time()
            timeout = 3.0  # Same as working test
            
            while time.time() - start_time < timeout:
                if self.server_process.poll() is not None:
                    raise SemgrepServerError(f"Server died with exit code: {self.server_process.poll()}")
                
                ready, _, _ = select.select([self.server_process.stdout], [], [], 0.1)
                if ready:
                    line = self.server_process.stdout.readline()
                    if line and line.strip():
                        response_line = line.strip()
                        logger.debug(f"Received response: {response_line[:100]}...")
                        break
                
                time.sleep(0.01)
            
            if not response_line:
                raise SemgrepProtocolError(f"No initialize response after {timeout}s")
            
            # Parse response - exact copy of working test
            response = json.loads(response_line)
            
            if "error" in response:
                error_detail = response["error"]
                logger.error(f"Initialize failed: {error_detail}")
                raise SemgrepProtocolError(f"Initialize failed: {error_detail}")
            
            if "result" not in response:
                raise SemgrepProtocolError(f"Invalid initialize response: {response}")

            logger.debug("Initialize response OK")

            # Send initialized notification (REQUIRED after initialize)
            initialized_notification = {
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
                "params": {}
            }

            notification_json = json.dumps(initialized_notification) + "\n"
            self.server_process.stdin.write(notification_json)
            self.server_process.stdin.flush()

            # No wait needed - same as working test
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
            from .serialization_utils import safe_json_dumps, safe_json_loads
            request_json = safe_json_dumps(request, raise_on_error=True, context="mcp_request") + "\n"
            self.server_process.stdin.write(request_json)
            self.server_process.stdin.flush()
            
            # Đọc response với timeout
            response_line = self._read_response_with_timeout()
            if not response_line:
                raise SemgrepProtocolError("No response from server")
                
            response = safe_json_loads(response_line, raise_on_error=True, context="mcp_response")
            return response
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
            from .serialization_utils import safe_json_dumps
            notification_json = safe_json_dumps(notification, raise_on_error=True, context="mcp_notification") + "\n"
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
        Gửi yêu cầu MCP đến server với improved retry logic và progressive timeout
        
        Args:
            method: Tên method MCP
            params: Tham số cho method
            
        Returns:
            Kết quả từ server
        """
        last_exception = None
        
        for attempt in range(self.max_retries):
            try:
                if not self.server_process or not self.initialized:
                    self.start_server()
                
                # Progressive timeout: tăng dần với mỗi lần retry
                progressive_timeout = self.timeout + (attempt * 15)  # +15s mỗi lần retry
                
                # Tạo JSON-RPC request theo MCP spec
                request = {
                    "jsonrpc": "2.0",
                    "id": self.request_id,
                    "method": method,
                    "params": params
                }
                self.request_id += 1
                
                logger.debug(f"Attempt {attempt + 1}: sending {method} request with {progressive_timeout}s timeout")
                response = self._send_request_with_timeout_extended(request, timeout=progressive_timeout)
                
                # Handle JSON-RPC response format first
                if "error" in response:
                    error_detail = response["error"]
                    logger.error(f"JSON-RPC Error: {error_detail}")
                    raise SemgrepProtocolError(f"JSON-RPC Error: {error_detail}")
                
                # Extract result from JSON-RPC response
                result = response.get("result", {})
                
                # Now handle MCP tool response format within result
                if isinstance(result, dict) and "content" in result:
                    if result.get("isError", False):
                        error_msg = result.get("content", "Unknown MCP tool error")
                        logger.error(f"MCP Tool Error: {error_msg}")
                        raise SemgrepProtocolError(f"MCP Tool Error: {error_msg}")
                    
                    # Parse the content - handle MCP format
                    content = result.get("content", [])
                    
                    # Handle list of content objects (typical MCP format)
                    if isinstance(content, list) and content:
                        first_content = content[0]
                        if isinstance(first_content, dict) and "text" in first_content:
                            # Extract JSON from text field
                            from .serialization_utils import safe_json_loads
                            text_content = first_content.get("text", "")
                            # Parse nested JSON safely
                            parsed_data = safe_json_loads(text_content, default=None, context="mcp_text_content")
                            if parsed_data is not None:
                                # Fix: Add total_findings if missing but results exist
                                if isinstance(parsed_data, dict) and "results" in parsed_data and "total_findings" not in parsed_data:
                                    parsed_data["total_findings"] = len(parsed_data["results"])
                                logger.info(f"Request {method} completed successfully")
                                return parsed_data
                            else:
                                return {"raw_output": text_content}
                        else:
                            # Return first content object as-is
                            return first_content
                    elif isinstance(content, str):
                        # Try to parse string content as JSON safely
                        from .serialization_utils import safe_json_loads
                        parsed_content = safe_json_loads(content, default=None, context="mcp_string_content")
                        if parsed_content is not None:
                            return parsed_content
                        else:
                            # If not JSON, return as is in a structured format
                            return {"raw_output": content}
                    else:
                        # Return content as-is
                        return content
                
                # Fallback: return result as-is
                logger.info(f"Request {method} completed successfully")
                return result
                
            except (SemgrepServerError, SemgrepProtocolError) as e:
                last_exception = e
                self.error_counts["connection_errors"] += 1
                logger.warning(f"Attempt {attempt + 1}/{self.max_retries} failed: {e}")
                
                if attempt < self.max_retries - 1:
                    wait_time = 2 ** attempt  # Exponential backoff: 2s, 4s, 8s
                    logger.info(f"Retrying in {wait_time} seconds...")
                    time.sleep(wait_time)
                    self._cleanup_server()  # Reset connection
                else:
                    logger.error(f"All {self.max_retries} attempts failed")
                
            except Exception as e:
                last_exception = e
                logger.error(f"Unexpected error in send_mcp_request: {e}")
                self._cleanup_server()
                
                if attempt < self.max_retries - 1:
                    wait_time = 2 ** attempt
                    logger.info(f"Retrying after unexpected error in {wait_time} seconds...")
                    time.sleep(wait_time)
                else:
                    logger.error(f"All {self.max_retries} attempts failed with unexpected error")
        
        # Nếu tất cả attempts đều thất bại
        raise SemgrepMCPError(f"All {self.max_retries} attempts failed. Last error: {last_exception}")
    
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
        
        # Nếu không có config, sử dụng comprehensive config
        if not config:
            config = self._build_comprehensive_config()
        
        params = {"code_files": code_files}
        if config:
            params["config"] = config
            
        return self.send_mcp_request("tools/call", {
            "name": "semgrep_scan",
            "arguments": {
                "code_files": code_files,
                "config": config
            }
        })
    
    def _build_comprehensive_config(self) -> str:
        """Build comprehensive config string với custom rules - MCP compatible"""
        from .config import get_config
        import os
        
        # MCP Semgrep tool expects single config or absolute path to file
        # Can't use multiple configs like CLI, so prioritize most important
        
        cfg = get_config()
        comprehensive_rules = cfg.get("SEMGREP_RULES_CONFIG", {}).get("comprehensive", [])
        
        # Check if custom rules file exists
        custom_rules_path = os.path.join(os.path.dirname(__file__), "custom_rules.yaml")
        if os.path.exists(custom_rules_path):
            # Use custom rules file (absolute path)
            return os.path.abspath(custom_rules_path)
        
        # Fallback to single best config
        if comprehensive_rules:
            # Use first comprehensive rule or auto
            first_rule = comprehensive_rules[0] if comprehensive_rules else "auto"
            return first_rule
        
        return "auto"
    
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
            # Web & General
            '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.cpp', '.c', '.h',
            '.cs', '.php', '.rb', '.go', '.rs', '.swift', '.scala',
            '.html', '.xml', '.yaml', '.yml', '.json', '.sql', '.sh', '.bash',
            '.vue', '.lua', '.r', '.tf', '.hcl', '.sol',
            
            # Android & Mobile
            '.kt', '.kts',  # Kotlin files
            '.dart',        # Flutter/Dart files
            '.gradle',      # Android Gradle files
            '.properties',  # Android properties
            '.pro',         # ProGuard files
            '.cfg',         # Config files
            
            # Android XML & Resources
            '.axml',        # Android XML
            '.arsc',        # Android Resource
            '.smali',       # Smali files
            
            # Mobile Config & Manifests
            '.plist',       # iOS plist
            '.entitlements', # iOS entitlements
            '.xcconfig',    # Xcode config
            '.pbxproj',     # Xcode project
            '.storyboard',  # iOS storyboard
            '.xib',         # iOS Interface Builder
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
            
            # Sử dụng comprehensive config nếu không có config
            if not config:
                config = self._build_comprehensive_config()
                
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
    
    def scan_for_secrets(self, code_files: List[Dict[str, str]], 
                        config: Optional[str] = None) -> Dict[str, Any]:
        """
        Scan code files để phát hiện secrets và thông tin nhạy cảm
        
        Args:
            code_files: Danh sách files với 'filename' và 'content'
            config: Cấu hình Semgrep tùy chỉnh
            
        Returns:
            Kết quả scan tập trung vào secrets
        """
        if not code_files:
            return {"status": "error", "message": "No code files provided"}
        
        # Sử dụng rules tập trung vào secrets nếu không có config tùy chỉnh
        if not config:
            from .config import get_config
            cfg = get_config()
            if cfg.get("ENABLE_SECRETS_DETECTION", True):
                secrets_rules = cfg.get("SEMGREP_RULES_CONFIG", {}).get("secrets", [])
                config = " ".join(secrets_rules) if secrets_rules else "auto"
        
        params = {
            "code_files": code_files,
            "config": config or "r/secrets"
        }
            
        result = self.send_mcp_request("tools/call", {
            "name": "semgrep_scan",
            "arguments": params
        })
        
        # Post-process kết quả để filter và classify secrets
        if result.get("status") == "success" and "results" in result:
            result = self._enhance_secrets_results(result)
        
        return result
    
    def scan_android_project(self, code_files: List[Dict[str, str]], 
                           config: Optional[str] = None) -> Dict[str, Any]:
        """
        Scan Android project để tìm lỗ hổng bảo mật mobile-specific
        
        Args:
            code_files: Danh sách files với 'filename' và 'content'
            config: Cấu hình Semgrep tùy chỉnh
            
        Returns:
            Kết quả scan tập trung vào Android/mobile security
        """
        if not code_files:
            return {"status": "error", "message": "No code files provided"}
        
        # Filter files relevant to Android
        android_files = []
        for file_info in code_files:
            filename = file_info.get("filename", "").lower()
            if any(ext in filename for ext in ['.kt', '.java', '.xml', '.gradle', '.properties']):
                android_files.append(file_info)
        
        if not android_files:
            return {
                "status": "warning", 
                "message": "No Android-specific files found",
                "total_files_checked": len(code_files)
            }
        
        # Sử dụng Android-specific rules
        if not config:
            from .config import get_config
            cfg = get_config()
            if cfg.get("ENABLE_ANDROID_SUPPORT", True):
                android_rules = cfg.get("SEMGREP_RULES_CONFIG", {}).get("android", [])
                mobile_rules = cfg.get("SEMGREP_RULES_CONFIG", {}).get("mobile_general", [])
                all_rules = android_rules + mobile_rules
                config = " ".join(all_rules) if all_rules else "r/java.android r/kotlin.android"
        
        params = {
            "code_files": android_files,
            "config": config or "r/java.android r/kotlin.android"
        }
            
        result = self.send_mcp_request("tools/call", {
            "name": "semgrep_scan",
            "arguments": params
        })
        
        # Post-process để add Android-specific context
        if result.get("status") == "success":
            result = self._enhance_android_results(result, len(code_files))
        
        return result
    
    def scan_flutter_project(self, code_files: List[Dict[str, str]], 
                           config: Optional[str] = None) -> Dict[str, Any]:
        """
        Scan Flutter/Dart project để tìm lỗ hổng bảo mật
        
        Args:
            code_files: Danh sách files với 'filename' và 'content'
            config: Cấu hình Semgrep tùy chỉnh
            
        Returns:
            Kết quả scan tập trung vào Flutter/Dart security
        """
        if not code_files:
            return {"status": "error", "message": "No code files provided"}
        
        # Filter files relevant to Flutter
        flutter_files = []
        for file_info in code_files:
            filename = file_info.get("filename", "").lower()
            if any(ext in filename for ext in ['.dart', '.yaml', '.yml']):
                flutter_files.append(file_info)
        
        if not flutter_files:
            return {
                "status": "warning", 
                "message": "No Flutter-specific files found",
                "total_files_checked": len(code_files)
            }
        
        # Sử dụng Flutter-specific rules
        if not config:
            from .config import get_config
            cfg = get_config()
            if cfg.get("ENABLE_ANDROID_SUPPORT", True):  # Flutter cũng thuộc mobile
                flutter_rules = cfg.get("SEMGREP_RULES_CONFIG", {}).get("flutter", [])
                config = " ".join(flutter_rules) if flutter_rules else "r/dart.flutter"
        
        params = {
            "code_files": flutter_files,
            "config": config or "r/dart.flutter"
        }
            
        result = self.send_mcp_request("tools/call", {
            "name": "semgrep_scan",
            "arguments": params
        })
        
        # Post-process để add Flutter-specific context
        if result.get("status") == "success":
            result = self._enhance_flutter_results(result, len(code_files))
        
        return result
    
    def _enhance_secrets_results(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Enhance secrets scan results với additional analysis"""
        try:
            from .config import get_config
            cfg = get_config()
            
            enhanced_results = []
            secrets_count = 0
            high_entropy_count = 0
            
            for finding in result.get("results", []):
                # Classify loại secret
                rule_id = finding.get("check_id", "").lower()
                message = finding.get("message", "").lower()
                
                finding["secret_type"] = "unknown"
                finding["risk_level"] = "medium"
                
                # Classify theo rule patterns
                if any(keyword in rule_id for keyword in ["password", "pwd"]):
                    finding["secret_type"] = "password"
                    finding["risk_level"] = "high"
                elif any(keyword in rule_id for keyword in ["api", "key", "token"]):
                    finding["secret_type"] = "api_credential"
                    finding["risk_level"] = "high"
                elif any(keyword in rule_id for keyword in ["database", "db", "connection"]):
                    finding["secret_type"] = "database_credential"
                    finding["risk_level"] = "critical"
                elif "private" in rule_id:
                    finding["secret_type"] = "private_key"
                    finding["risk_level"] = "critical"
                elif any(keyword in rule_id for keyword in ["secret", "credential"]):
                    finding["secret_type"] = "generic_secret"
                    finding["risk_level"] = "high"
                
                # Đếm các loại secrets
                if finding["secret_type"] != "unknown":
                    secrets_count += 1
                    
                if finding["risk_level"] in ["high", "critical"]:
                    high_entropy_count += 1
                
                enhanced_results.append(finding)
            
            # Thêm summary thống kê
            result["secrets_summary"] = {
                "total_secrets_found": secrets_count,
                "high_risk_secrets": high_entropy_count,
                "secret_types_detected": list(set(
                    r["secret_type"] for r in enhanced_results 
                    if r["secret_type"] != "unknown"
                ))
            }
            
            result["results"] = enhanced_results
            
        except Exception as e:
            logger.warning(f"Error enhancing secrets results: {e}")
        
        return result
    
    def _enhance_android_results(self, result: Dict[str, Any], total_files: int) -> Dict[str, Any]:
        """Enhance Android scan results với mobile-specific analysis"""
        try:
            enhanced_results = []
            permissions_issues = 0
            security_config_issues = 0
            
            for finding in result.get("results", []):
                rule_id = finding.get("check_id", "").lower()
                
                # Classify Android-specific issues
                finding["android_category"] = "general"
                
                if any(keyword in rule_id for keyword in ["permission", "manifest"]):
                    finding["android_category"] = "permissions"
                    permissions_issues += 1
                elif any(keyword in rule_id for keyword in ["network", "https", "ssl", "tls"]):
                    finding["android_category"] = "network_security"
                elif any(keyword in rule_id for keyword in ["storage", "file", "external"]):
                    finding["android_category"] = "data_storage"
                elif "intent" in rule_id:
                    finding["android_category"] = "intent_security"
                elif any(keyword in rule_id for keyword in ["crypto", "encryption"]):
                    finding["android_category"] = "cryptography"
                elif "debug" in rule_id:
                    finding["android_category"] = "debug_security"
                    security_config_issues += 1
                
                enhanced_results.append(finding)
            
            # Thêm Android-specific summary
            result["android_summary"] = {
                "total_android_files": total_files,
                "permissions_issues": permissions_issues,
                "security_config_issues": security_config_issues,
                "categories_affected": list(set(
                    r["android_category"] for r in enhanced_results
                ))
            }
            
            result["results"] = enhanced_results
            
        except Exception as e:
            logger.warning(f"Error enhancing Android results: {e}")
        
        return result
    
    def _enhance_flutter_results(self, result: Dict[str, Any], total_files: int) -> Dict[str, Any]:
        """Enhance Flutter scan results với Flutter-specific analysis"""
        try:
            enhanced_results = []
            dependency_issues = 0
            platform_channel_issues = 0
            
            for finding in result.get("results", []):
                rule_id = finding.get("check_id", "").lower()
                
                # Classify Flutter-specific issues
                finding["flutter_category"] = "general"
                
                if any(keyword in rule_id for keyword in ["pubspec", "dependency"]):
                    finding["flutter_category"] = "dependencies"
                    dependency_issues += 1
                elif any(keyword in rule_id for keyword in ["platform", "channel", "method"]):
                    finding["flutter_category"] = "platform_channels"
                    platform_channel_issues += 1
                elif any(keyword in rule_id for keyword in ["widget", "state"]):
                    finding["flutter_category"] = "widget_security"
                elif any(keyword in rule_id for keyword in ["navigation", "route"]):
                    finding["flutter_category"] = "navigation"
                elif any(keyword in rule_id for keyword in ["async", "future", "stream"]):
                    finding["flutter_category"] = "async_security"
                
                enhanced_results.append(finding)
            
            # Thêm Flutter-specific summary
            result["flutter_summary"] = {
                "total_flutter_files": total_files,
                "dependency_issues": dependency_issues,
                "platform_channel_issues": platform_channel_issues,
                "categories_affected": list(set(
                    r["flutter_category"] for r in enhanced_results
                ))
            }
            
            result["results"] = enhanced_results
            
        except Exception as e:
            logger.warning(f"Error enhancing Flutter results: {e}")
        
        return result
    
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

    def _send_request_with_timeout_extended(self, request: Dict[str, Any], timeout: int = None) -> Dict[str, Any]:
        """Gửi request với timeout - simplified version like debug_response.py"""
        if not self._is_server_running():
            raise SemgrepServerError("Server process not running")
        
        try:
            # Use exact same approach as working debug_response.py
            import json
            import select
            
            request_json = json.dumps(request) + "\n"
            
            logger.debug(f"Sending MCP request: {request_json.strip()}")
            self.server_process.stdin.write(request_json)
            self.server_process.stdin.flush()
            
            # Sử dụng timeout tùy chỉnh hoặc timeout mặc định
            actual_timeout = timeout or self.timeout
            logger.debug(f"Waiting for response with timeout: {actual_timeout}s")
            
            # Simple approach like debug_response.py - just use select and readline
            ready, _, _ = select.select([self.server_process.stdout], [], [], actual_timeout)
            if ready:
                response_line = self.server_process.stdout.readline().strip()
                logger.debug(f"Received response: {response_line[:100]}...")
                
                if response_line:
                    response = json.loads(response_line)
                    return response
                else:
                    raise SemgrepProtocolError("Empty response from server")
            else:
                self.error_counts["timeout_errors"] += 1
                raise SemgrepProtocolError(f"No response from server after {actual_timeout}s")
            
        except json.JSONDecodeError as e:
            logger.error(f"JSON decode error: {e}")
            raise SemgrepProtocolError(f"Invalid JSON response: {e}")
        except BrokenPipeError:
            logger.error("Broken pipe to server")
            self.error_counts["connection_errors"] += 1
            self._cleanup_server()
            raise SemgrepServerError("Connection to server lost")
        except Exception as e:
            logger.error(f"Request failed: {e}")
            raise SemgrepProtocolError(f"Request failed: {e}")


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

class CircuitBreaker:
    """Simple circuit breaker để tránh overload server"""
    
    def __init__(self, failure_threshold: int = 5, reset_timeout: int = 300):
        self.failure_threshold = failure_threshold
        self.reset_timeout = reset_timeout
        self.failure_count = 0
        self.last_failure_time = 0
        self.state = "CLOSED"  # CLOSED, OPEN, HALF_OPEN
        self._lock = threading.Lock()
    
    def call(self, func):
        """Execute function with circuit breaker protection"""
        with self._lock:
            if self.state == "OPEN":
                if time.time() - self.last_failure_time > self.reset_timeout:
                    self.state = "HALF_OPEN"
                    logger.info("Circuit breaker switching to HALF_OPEN")
                else:
                    raise CodeScanException(
                        code=ErrorCode.RESOURCE_EXHAUSTED,
                        message="Circuit breaker is OPEN - too many failures",
                        severity=ErrorSeverity.HIGH,
                        component="circuit_breaker"
                    )
            
            try:
                result = func()
                # Success - reset circuit breaker
                if self.state == "HALF_OPEN":
                    self.state = "CLOSED"
                    self.failure_count = 0
                    logger.info("Circuit breaker reset to CLOSED")
                return result
                
            except Exception as e:
                self.failure_count += 1
                self.last_failure_time = time.time()
                
                if self.failure_count >= self.failure_threshold:
                    self.state = "OPEN"
                    logger.warning(f"Circuit breaker OPEN after {self.failure_count} failures")
                
                raise e 