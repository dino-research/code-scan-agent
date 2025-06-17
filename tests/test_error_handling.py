"""
Test suite for the error handling framework of Code Scan Agent
"""
import unittest
import tempfile
import os
import time
from pathlib import Path
from unittest.mock import patch, MagicMock

from code_scan_agent.errors import (
    ErrorCode, ErrorSeverity, CodeScanException, CircuitBreaker,
    CircuitBreakerState, ErrorHandler, handle_errors, create_error_response
)
from code_scan_agent.agent import validate_directory_path, validate_file_paths
from code_scan_agent.semgrep_client import SemgrepSyncClient


class TestErrorCodes(unittest.TestCase):
    """Test error codes and severity levels"""
    
    def test_error_code_values(self):
        """Test that error codes have expected format"""
        for code in ErrorCode:
            self.assertTrue(code.value.startswith("E"))
            self.assertEqual(len(code.value), 5)
    
    def test_severity_levels(self):
        """Test severity level values"""
        expected_levels = ["critical", "high", "medium", "low", "info"]
        for severity in ErrorSeverity:
            self.assertIn(severity.value, expected_levels)


class TestCodeScanException(unittest.TestCase):
    """Test CodeScanException functionality"""
    
    def test_exception_creation(self):
        """Test creating a CodeScanException"""
        exception = CodeScanException(
            code=ErrorCode.INVALID_INPUT,
            message="Test error message",
            severity=ErrorSeverity.MEDIUM,
            component="test",
            operation="test_operation"
        )
        
        self.assertEqual(exception.error.code, ErrorCode.INVALID_INPUT)
        self.assertEqual(exception.error.message, "Test error message")
        self.assertEqual(exception.error.severity, ErrorSeverity.MEDIUM)
        self.assertEqual(exception.error.context.component, "test")
        self.assertEqual(exception.error.context.operation, "test_operation")
    
    def test_exception_to_dict(self):
        """Test converting exception to dictionary"""
        exception = CodeScanException(
            code=ErrorCode.INVALID_INPUT,
            message="Test error message",
            severity=ErrorSeverity.MEDIUM,
            component="test",
            operation="test_operation",
            recovery_suggestion="Fix the input"
        )
        
        error_dict = exception.to_dict()
        
        self.assertEqual(error_dict["error_code"], ErrorCode.INVALID_INPUT.value)
        self.assertEqual(error_dict["error_message"], "Test error message")
        self.assertEqual(error_dict["severity"], ErrorSeverity.MEDIUM.value)
        self.assertEqual(error_dict["component"], "test")
        self.assertEqual(error_dict["operation"], "test_operation")
        self.assertEqual(error_dict["recovery_suggestion"], "Fix the input")


class TestCircuitBreaker(unittest.TestCase):
    """Test CircuitBreaker functionality"""
    
    def test_circuit_breaker_initial_state(self):
        """Test initial state of circuit breaker"""
        cb = CircuitBreaker(failure_threshold=3, recovery_timeout=1)
        self.assertEqual(cb.state, CircuitBreakerState.CLOSED)
        self.assertEqual(cb.failure_count, 0)
    
    def test_circuit_breaker_open_after_failures(self):
        """Test circuit breaker opens after threshold failures"""
        cb = CircuitBreaker(failure_threshold=3, recovery_timeout=1)
        
        # Define a function that always fails
        def failing_function():
            raise Exception("Test failure")
        
        # Call the function 3 times (threshold)
        for _ in range(3):
            try:
                cb.call(failing_function)
            except Exception:
                pass
        
        self.assertEqual(cb.state, CircuitBreakerState.OPEN)
        self.assertEqual(cb.failure_count, 3)
    
    def test_circuit_breaker_half_open_after_timeout(self):
        """Test circuit breaker transitions to half-open after timeout"""
        cb = CircuitBreaker(failure_threshold=2, recovery_timeout=0.1)
        
        # Define a function that always fails
        def failing_function():
            raise Exception("Test failure")
        
        # Call the function to open the circuit
        for _ in range(2):
            try:
                cb.call(failing_function)
            except Exception:
                pass
        
        self.assertEqual(cb.state, CircuitBreakerState.OPEN)
        
        # Wait for recovery timeout
        time.sleep(0.2)
        
        # Try again - should be in half-open state
        try:
            cb.call(failing_function)
        except CodeScanException as e:
            self.fail("Should not raise CodeScanException in half-open state")
        except Exception:
            pass
        
        self.assertEqual(cb.state, CircuitBreakerState.OPEN)
    
    def test_circuit_breaker_closes_after_success(self):
        """Test circuit breaker closes after successful call"""
        cb = CircuitBreaker(failure_threshold=2, recovery_timeout=0.1)
        
        # Define functions
        def failing_function():
            raise Exception("Test failure")
            
        def successful_function():
            return "Success"
        
        # Call the function to open the circuit
        for _ in range(2):
            try:
                cb.call(failing_function)
            except Exception:
                pass
        
        self.assertEqual(cb.state, CircuitBreakerState.OPEN)
        
        # Wait for recovery timeout
        time.sleep(0.2)
        
        # Call with success function
        result = cb.call(successful_function)
        
        self.assertEqual(result, "Success")
        self.assertEqual(cb.state, CircuitBreakerState.CLOSED)
        self.assertEqual(cb.failure_count, 0)


class TestErrorHandler(unittest.TestCase):
    """Test ErrorHandler functionality"""
    
    def test_handle_error_with_code_scan_exception(self):
        """Test handling CodeScanException"""
        handler = ErrorHandler()
        
        exception = CodeScanException(
            code=ErrorCode.INVALID_INPUT,
            message="Test error message",
            severity=ErrorSeverity.MEDIUM,
            component="test",
            operation="test_operation"
        )
        
        result = handler.handle_error(exception, "test", "test_operation")
        
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["error_code"], ErrorCode.INVALID_INPUT.value)
        self.assertEqual(result["error_message"], "Test error message")
    
    def test_handle_error_with_standard_exception(self):
        """Test handling standard Exception"""
        handler = ErrorHandler()
        
        exception = ValueError("Test standard error")
        
        result = handler.handle_error(exception, "test", "test_operation")
        
        self.assertEqual(result["status"], "error")
        # The actual implementation maps standard exceptions to INVALID_INPUT (E1001)
        # rather than UNKNOWN_ERROR (E9001)
        self.assertEqual(result["error_code"], ErrorCode.INVALID_INPUT.value)
        self.assertEqual(result["error_message"], "Test standard error")
    
    def test_error_tracking(self):
        """Test error frequency tracking"""
        handler = ErrorHandler()
        
        # Create and handle multiple errors
        for _ in range(3):
            exception = CodeScanException(
                code=ErrorCode.INVALID_INPUT,
                message="Test error message",
                component="test",
                operation="test_operation"
            )
            handler.handle_error(exception, "test", "test_operation")
        
        stats = handler.get_error_stats()
        self.assertIn("error_counts", stats)
        self.assertIn(ErrorCode.INVALID_INPUT.value, stats["error_counts"])
        self.assertEqual(stats["error_counts"][ErrorCode.INVALID_INPUT.value], 3)


class TestHandleErrorsDecorator(unittest.TestCase):
    """Test handle_errors decorator"""
    
    def test_handle_errors_decorator_success(self):
        """Test decorator with successful function"""
        @handle_errors("test", "test_operation")
        def successful_function():
            return "Success"
        
        result = successful_function()
        self.assertEqual(result, "Success")
    
    def test_handle_errors_decorator_exception(self):
        """Test decorator with failing function"""
        @handle_errors("test", "test_operation")
        def failing_function():
            raise ValueError("Test error")
        
        result = failing_function()
        self.assertEqual(result["status"], "error")
        self.assertIn("error_message", result)
        self.assertEqual(result["error_message"], "Test error")


class TestAgentValidation(unittest.TestCase):
    """Test validation functions in agent.py"""
    
    def test_validate_directory_path_success(self):
        """Test successful directory validation"""
        with tempfile.TemporaryDirectory() as temp_dir:
            result = validate_directory_path(temp_dir)
            self.assertEqual(result, Path(temp_dir).resolve())
    
    def test_validate_directory_path_empty(self):
        """Test validation with empty directory path"""
        with self.assertRaises(CodeScanException) as context:
            validate_directory_path("")
        
        self.assertEqual(context.exception.error.code, ErrorCode.EMPTY_INPUT)
    
    def test_validate_directory_path_not_exists(self):
        """Test validation with non-existent directory"""
        with self.assertRaises(CodeScanException) as context:
            validate_directory_path("/path/does/not/exist")
        
        self.assertEqual(context.exception.error.code, ErrorCode.FILE_NOT_FOUND)
    
    def test_validate_file_paths_success(self):
        """Test successful file paths validation"""
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_file.write(b"test content")
            temp_file_path = temp_file.name
        
        try:
            result = validate_file_paths([temp_file_path])
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0], Path(temp_file_path).resolve())
        finally:
            os.unlink(temp_file_path)
    
    def test_validate_file_paths_empty_list(self):
        """Test validation with empty file paths list"""
        with self.assertRaises(CodeScanException) as context:
            validate_file_paths([])
        
        self.assertEqual(context.exception.error.code, ErrorCode.EMPTY_INPUT)


class TestSemgrepClient(unittest.TestCase):
    """Test SemgrepClient error handling"""
    
    @patch('subprocess.Popen')
    @patch('code_scan_agent.semgrep_client.SemgrepSyncClient._perform_preflight_checks')
    def test_start_server_error(self, mock_preflight, mock_popen):
        """Test error handling when server fails to start"""
        # Skip preflight checks that require psutil
        mock_preflight.return_value = None
        
        # Mock subprocess.Popen to raise an exception
        mock_popen.side_effect = FileNotFoundError("uvx not found")
        
        client = SemgrepSyncClient()
        
        # Patch circuit breaker to avoid actual circuit breaking
        client.circuit_breaker = MagicMock()
        client.circuit_breaker.call.side_effect = lambda f, *args, **kwargs: f(*args, **kwargs)
        
        # The start_server method is decorated with @handle_errors which catches exceptions
        # and returns a structured error response instead of raising
        result = client.start_server()
        
        # Check that the result is an error response with the correct error code
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["error_code"], ErrorCode.SERVER_START_FAILED.value)
        self.assertIn("uvx", result["error_message"])


if __name__ == "__main__":
    unittest.main() 