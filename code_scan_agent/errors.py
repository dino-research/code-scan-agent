"""
Comprehensive Error Handling Framework cho Code Scan Agent
Tuân thủ best practices từ Google ADK, MCP protocol và enterprise patterns
"""
import logging
import time
from enum import Enum
from typing import Dict, Any, Optional, Union, Callable
from dataclasses import dataclass
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


class ErrorSeverity(Enum):
    """Mức độ nghiêm trọng của lỗi"""
    CRITICAL = "critical"    # Hệ thống không thể hoạt động
    HIGH = "high"           # Chức năng chính bị ảnh hưởng
    MEDIUM = "medium"       # Chức năng phụ bị ảnh hưởng
    LOW = "low"            # Vấn đề nhỏ, không ảnh hưởng chức năng
    INFO = "info"          # Thông tin, không phải lỗi


class ErrorCode(Enum):
    """Mã lỗi chuẩn hóa cho tất cả components"""
    # Input Validation Errors (1000-1099)
    INVALID_INPUT = "E1001"
    EMPTY_INPUT = "E1002"
    INVALID_FILE_PATH = "E1003"
    INVALID_DIRECTORY = "E1004"
    FILE_NOT_FOUND = "E1005"
    FILE_TOO_LARGE = "E1006"
    UNSUPPORTED_FILE_TYPE = "E1007"
    INVALID_LANGUAGE = "E1008"
    INVALID_CONFIG = "E1009"
    
    # Semgrep Client Errors (2000-2099)
    CLIENT_INIT_FAILED = "E2001"
    SERVER_START_FAILED = "E2002"
    SERVER_NOT_RUNNING = "E2003"
    CONNECTION_LOST = "E2004"
    REQUEST_TIMEOUT = "E2005"
    PROTOCOL_ERROR = "E2006"
    INVALID_RESPONSE = "E2007"
    SERVER_CRASHED = "E2008"
    AUTHENTICATION_FAILED = "E2009"
    
    # MCP Protocol Errors (3000-3099)
    MCP_INIT_FAILED = "E3001"
    MCP_INVALID_REQUEST = "E3002"
    MCP_INVALID_RESPONSE = "E3003"
    MCP_METHOD_NOT_FOUND = "E3004"
    MCP_INVALID_PARAMS = "E3005"
    MCP_INTERNAL_ERROR = "E3006"
    MCP_PARSE_ERROR = "E3007"
    
    # Scan Operation Errors (4000-4099)
    SCAN_FAILED = "E4001"
    SCAN_TIMEOUT = "E4002"
    SCAN_INTERRUPTED = "E4003"
    INVALID_SCAN_CONFIG = "E4004"
    SCAN_RESULT_PARSE_ERROR = "E4005"
    CUSTOM_RULE_INVALID = "E4006"
    
    # System/Infrastructure Errors (5000-5099)
    SYSTEM_ERROR = "E5001"
    RESOURCE_EXHAUSTED = "E5002"
    PERMISSION_DENIED = "E5003"
    NETWORK_ERROR = "E5004"
    DISK_FULL = "E5005"
    MEMORY_ERROR = "E5006"
    
    # Configuration Errors (6000-6099)
    CONFIG_MISSING = "E6001"
    CONFIG_INVALID = "E6002"
    ENV_VAR_MISSING = "E6003"
    CREDENTIALS_INVALID = "E6004"
    
    # Unknown/Generic Errors (9000-9099)
    UNKNOWN_ERROR = "E9001"
    UNEXPECTED_ERROR = "E9002"


@dataclass
class ErrorContext:
    """Context thông tin cho error tracking và debugging"""
    component: str
    operation: str
    timestamp: datetime
    request_id: Optional[str] = None
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    additional_data: Optional[Dict[str, Any]] = None


@dataclass
class CodeScanError:
    """Structured error với complete context"""
    code: ErrorCode
    message: str
    severity: ErrorSeverity
    context: ErrorContext
    original_exception: Optional[Exception] = None
    recovery_suggestion: Optional[str] = None
    retry_after: Optional[int] = None  # seconds
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API responses"""
        return {
            "error_code": self.code.value,
            "error_message": self.message,
            "severity": self.severity.value,
            "timestamp": self.context.timestamp.isoformat(),
            "component": self.context.component,
            "operation": self.context.operation,
            "recovery_suggestion": self.recovery_suggestion,
            "retry_after": self.retry_after,
            "request_id": self.context.request_id,
            "additional_data": self.context.additional_data
        }
    
    def __str__(self) -> str:
        return f"[{self.code.value}] {self.message} (severity: {self.severity.value})"


class CircuitBreakerState(Enum):
    """Circuit breaker states"""
    CLOSED = "closed"      # Normal operation
    OPEN = "open"         # Failing, reject requests
    HALF_OPEN = "half_open"  # Testing recovery


class CircuitBreaker:
    """Circuit breaker pattern implementation cho service protection"""
    
    def __init__(self, 
                 failure_threshold: int = 5,
                 recovery_timeout: int = 60,
                 expected_exception: type = Exception):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.expected_exception = expected_exception
        
        self.failure_count = 0
        self.last_failure_time = None
        self.state = CircuitBreakerState.CLOSED
        
    def call(self, func: Callable, *args, **kwargs):
        """Execute function với circuit breaker protection"""
        if self.state == CircuitBreakerState.OPEN:
            if self._should_attempt_reset():
                self.state = CircuitBreakerState.HALF_OPEN
            else:
                raise CodeScanException(
                    code=ErrorCode.SERVER_NOT_RUNNING,
                    message="Circuit breaker is OPEN - service temporarily unavailable",
                    severity=ErrorSeverity.HIGH,
                    recovery_suggestion=f"Wait {self.recovery_timeout} seconds for auto-recovery",
                    retry_after=self.recovery_timeout
                )
        
        try:
            result = func(*args, **kwargs)
            self._on_success()
            return result
        except self.expected_exception as e:
            self._on_failure()
            raise e
    
    def _should_attempt_reset(self) -> bool:
        """Check if should attempt to reset circuit breaker"""
        return (self.last_failure_time and 
                time.time() - self.last_failure_time >= self.recovery_timeout)
    
    def _on_success(self):
        """Handle successful call"""
        self.failure_count = 0
        self.state = CircuitBreakerState.CLOSED
    
    def _on_failure(self):
        """Handle failed call"""
        self.failure_count += 1
        self.last_failure_time = time.time()
        
        if self.failure_count >= self.failure_threshold:
            self.state = CircuitBreakerState.OPEN


class CodeScanException(Exception):
    """Base exception class với structured error information"""
    
    def __init__(self, 
                 code: ErrorCode,
                 message: str,
                 severity: ErrorSeverity = ErrorSeverity.MEDIUM,
                 component: str = "unknown",
                 operation: str = "unknown",
                 original_exception: Optional[Exception] = None,
                 recovery_suggestion: Optional[str] = None,
                 retry_after: Optional[int] = None,
                 **context_data):
        
        super().__init__(message)
        
        self.error = CodeScanError(
            code=code,
            message=message,
            severity=severity,
            context=ErrorContext(
                component=component,
                operation=operation,
                timestamp=datetime.now(),
                additional_data=context_data
            ),
            original_exception=original_exception,
            recovery_suggestion=recovery_suggestion,
            retry_after=retry_after
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API responses"""
        return self.error.to_dict()


class ErrorHandler:
    """Centralized error handler với logging và monitoring"""
    
    def __init__(self):
        self.error_counts = {}  # Error frequency tracking
        self.circuit_breakers = {}  # Circuit breakers per service
    
    def handle_error(self, 
                    error: Union[Exception, CodeScanException],
                    component: str,
                    operation: str,
                    **context) -> Dict[str, Any]:
        """
        Central error handling với logging và structured response
        
        Args:
            error: Exception được catch
            component: Component name (e.g., 'semgrep_client', 'agent')
            operation: Operation name (e.g., 'scan_directory', 'start_server')
            **context: Additional context data
            
        Returns:
            Structured error response
        """
        if isinstance(error, CodeScanException):
            code_scan_error = error.error
        else:
            # Convert standard exception to CodeScanError
            code_scan_error = self._convert_exception_to_code_scan_error(
                error, component, operation, **context
            )
        
        # Log error
        self._log_error(code_scan_error)
        
        # Track error frequency
        self._track_error_frequency(code_scan_error.code)
        
        # Return structured response
        return {
            "status": "error",
            **code_scan_error.to_dict()
        }
    
    def _convert_exception_to_code_scan_error(self, 
                                            exception: Exception,
                                            component: str,
                                            operation: str,
                                            **context) -> CodeScanError:
        """Convert standard exception to structured CodeScanError"""
        
        # Map common exceptions to error codes
        exception_mapping = {
            FileNotFoundError: (ErrorCode.FILE_NOT_FOUND, ErrorSeverity.MEDIUM),
            NotADirectoryError: (ErrorCode.INVALID_DIRECTORY, ErrorSeverity.MEDIUM),
            ValueError: (ErrorCode.INVALID_INPUT, ErrorSeverity.MEDIUM),
            ConnectionError: (ErrorCode.CONNECTION_LOST, ErrorSeverity.HIGH),
            TimeoutError: (ErrorCode.REQUEST_TIMEOUT, ErrorSeverity.HIGH),
            PermissionError: (ErrorCode.PERMISSION_DENIED, ErrorSeverity.HIGH),
            MemoryError: (ErrorCode.MEMORY_ERROR, ErrorSeverity.CRITICAL),
        }
        
        error_code, severity = exception_mapping.get(
            type(exception), 
            (ErrorCode.UNEXPECTED_ERROR, ErrorSeverity.MEDIUM)
        )
        
        # Generate recovery suggestion
        recovery_suggestion = self._generate_recovery_suggestion(error_code, exception)
        
        return CodeScanError(
            code=error_code,
            message=str(exception),
            severity=severity,
            context=ErrorContext(
                component=component,
                operation=operation,
                timestamp=datetime.now(),
                additional_data=context
            ),
            original_exception=exception,
            recovery_suggestion=recovery_suggestion
        )
    
    def _generate_recovery_suggestion(self, 
                                    error_code: ErrorCode, 
                                    exception: Exception) -> Optional[str]:
        """Generate helpful recovery suggestions based on error type"""
        
        suggestions = {
            ErrorCode.FILE_NOT_FOUND: "Kiểm tra đường dẫn file có tồn tại và accessible",
            ErrorCode.INVALID_DIRECTORY: "Đảm bảo đường dẫn là một thư mục hợp lệ",
            ErrorCode.PERMISSION_DENIED: "Kiểm tra quyền truy cập file/thư mục",
            ErrorCode.CONNECTION_LOST: "Kiểm tra kết nối mạng và khởi động lại service",
            ErrorCode.REQUEST_TIMEOUT: "Thử tăng timeout hoặc kiểm tra hiệu suất hệ thống",
            ErrorCode.SERVER_START_FAILED: "Kiểm tra uvx installation và dependencies",
            ErrorCode.MEMORY_ERROR: "Giảm kích thước input hoặc tăng memory available",
            ErrorCode.FILE_TOO_LARGE: "Chia nhỏ file hoặc loại trừ file lớn khỏi scan",
        }
        
        return suggestions.get(error_code)
    
    def _log_error(self, error: CodeScanError):
        """Log error với appropriate level"""
        log_msg = f"[{error.code.value}] {error.message}"
        
        extra_info = {
            'error_code': error.code.value,
            'component': error.context.component,
            'operation': error.context.operation,
            'timestamp': error.context.timestamp,
            'additional_data': error.context.additional_data
        }
        
        if error.severity == ErrorSeverity.CRITICAL:
            logger.critical(log_msg, extra=extra_info)
        elif error.severity == ErrorSeverity.HIGH:
            logger.error(log_msg, extra=extra_info)
        elif error.severity == ErrorSeverity.MEDIUM:
            logger.warning(log_msg, extra=extra_info)
        else:
            logger.info(log_msg, extra=extra_info)
    
    def _track_error_frequency(self, error_code: ErrorCode):
        """Track error frequency for monitoring"""
        self.error_counts[error_code.value] = self.error_counts.get(error_code.value, 0) + 1
    
    def get_circuit_breaker(self, service_name: str) -> CircuitBreaker:
        """Get hoặc tạo circuit breaker cho service"""
        if service_name not in self.circuit_breakers:
            self.circuit_breakers[service_name] = CircuitBreaker()
        return self.circuit_breakers[service_name]
    
    def get_error_stats(self) -> Dict[str, Any]:
        """Get error statistics for monitoring"""
        return {
            "error_counts": self.error_counts,
            "circuit_breaker_states": {
                name: cb.state.value 
                for name, cb in self.circuit_breakers.items()
            }
        }


# Global error handler instance
error_handler = ErrorHandler()


def handle_errors(component: str, operation: str = None):
    """Decorator để tự động handle errors"""
    def decorator(func):
        import functools
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            op_name = operation or func.__name__
            try:
                return func(*args, **kwargs)
            except Exception as e:
                return error_handler.handle_error(e, component, op_name)
        return wrapper
    return decorator


def create_error_response(error_code: ErrorCode,
                         message: str,
                         severity: ErrorSeverity = ErrorSeverity.MEDIUM,
                         **kwargs) -> Dict[str, Any]:
    """Utility function để tạo standardized error response"""
    error = CodeScanError(
        code=error_code,
        message=message,
        severity=severity,
        context=ErrorContext(
            component=kwargs.get('component', 'unknown'),
            operation=kwargs.get('operation', 'unknown'),
            timestamp=datetime.now(),
            additional_data=kwargs
        )
    )
    
    return {
        "status": "error",
        **error.to_dict()
    } 