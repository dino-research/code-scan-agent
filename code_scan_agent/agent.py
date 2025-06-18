"""
Code Scan Agent - Main agent module

AI-powered code security scanning tool that combines Google ADK with Semgrep MCP
to identify vulnerabilities, code quality issues, and security threats.

Features:
- Multi-language security scanning (40+ languages)
- AI-powered vulnerability analysis and explanations
- Custom rule support
- Comprehensive error handling with circuit breaker patterns
- OWASP Top 10 vulnerability detection
"""
import atexit
import concurrent.futures
import json
import logging
import os
import threading
from pathlib import Path
from typing import Dict, List, Any, Optional, Union

from .semgrep_client import SemgrepSyncClient, SemgrepMCPError, SemgrepServerError
from .errors import (
    ErrorCode, ErrorSeverity, CodeScanException, error_handler,
    handle_errors, create_error_response
)

# Cấu hình logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Thread-safe client management với improved lifecycle
_client_lock = threading.Lock()
_semgrep_client = None

# Pure Google ADK implementation
from google.adk.agents import LlmAgent as ADKAgent
logger.info("Using Google ADK LlmAgent")


def get_semgrep_client() -> SemgrepSyncClient:
    """
    Lấy hoặc tạo Semgrep client instance (thread-safe)
    Sử dụng singleton pattern với proper cleanup
    """
    global _semgrep_client
    
    with _client_lock:
        if _semgrep_client is None:
            try:
                _semgrep_client = SemgrepSyncClient(timeout=30, max_retries=3)
                logger.info("Created new Semgrep client instance")
            except Exception as e:
                logger.error(f"Failed to create Semgrep client: {e}")
                raise SemgrepMCPError(f"Client creation failed: {e}")
        return _semgrep_client


def cleanup_semgrep_client():
    """Cleanup Semgrep client với proper error handling"""
    global _semgrep_client
    
    with _client_lock:
        if _semgrep_client is not None:
            try:
                _semgrep_client.stop_server()
                _semgrep_client = None
                logger.info("Semgrep client cleaned up successfully")
            except Exception as e:
                logger.warning(f"Error during client cleanup: {e}")
                _semgrep_client = None  # Force reset even if cleanup fails


atexit.register(cleanup_semgrep_client)


def validate_directory_path(directory_path: str) -> Path:
    """Validate và normalize directory path với comprehensive error handling"""
    if not directory_path or not directory_path.strip():
        raise CodeScanException(
            code=ErrorCode.EMPTY_INPUT,
            message="Directory path cannot be empty",
            severity=ErrorSeverity.MEDIUM,
            component="agent",
            operation="validate_directory_path"
        )
    
    try:
        path = Path(directory_path).resolve()
    except Exception as e:
        raise CodeScanException(
            code=ErrorCode.INVALID_FILE_PATH,
            message=f"Invalid directory path format: {directory_path}",
            severity=ErrorSeverity.MEDIUM,
            component="agent",
            operation="validate_directory_path",
            original_exception=e
        )
    
    if not path.exists():
        raise CodeScanException(
            code=ErrorCode.FILE_NOT_FOUND,
            message=f"Directory does not exist: {directory_path}",
            severity=ErrorSeverity.MEDIUM,
            component="agent",
            operation="validate_directory_path",
            recovery_suggestion="Kiểm tra đường dẫn có tồn tại và accessible"
        )
    
    if not path.is_dir():
        raise CodeScanException(
            code=ErrorCode.INVALID_DIRECTORY,
            message=f"Path is not a directory: {directory_path}",
            severity=ErrorSeverity.MEDIUM,
            component="agent",
            operation="validate_directory_path",
            recovery_suggestion="Đảm bảo đường dẫn trỏ đến một thư mục, không phải file"
        )
    
    # Additional security checks
    try:
        # Check if directory is readable
        list(path.iterdir())
    except PermissionError:
        raise CodeScanException(
            code=ErrorCode.PERMISSION_DENIED,
            message=f"Permission denied accessing directory: {directory_path}",
            severity=ErrorSeverity.HIGH,
            component="agent",
            operation="validate_directory_path",
            recovery_suggestion="Kiểm tra quyền truy cập thư mục"
        )
    
    return path


def validate_file_paths(file_paths: List[str]) -> List[Path]:
    """Validate và normalize file paths với enhanced error handling"""
    if not file_paths:
        raise CodeScanException(
            code=ErrorCode.EMPTY_INPUT,
            message="File paths list cannot be empty",
            severity=ErrorSeverity.MEDIUM,
            component="agent",
            operation="validate_file_paths"
        )
    
    validated_paths = []
    invalid_files = []
    
    for i, file_path in enumerate(file_paths):
        if not file_path or not file_path.strip():
            continue
            
        try:
            path = Path(file_path).resolve()
        except Exception as e:
            invalid_files.append(f"Path {i}: Invalid format - {file_path}")
            continue
        
        if not path.exists():
            invalid_files.append(f"Path {i}: File not found - {file_path}")
            continue
        
        if not path.is_file():
            invalid_files.append(f"Path {i}: Not a file - {file_path}")
            continue
        
        # Check file size (skip very large files)
        try:
            file_size = path.stat().st_size
            if file_size > 10 * 1024 * 1024:  # 10MB limit
                invalid_files.append(f"Path {i}: File too large ({file_size / 1024 / 1024:.1f}MB) - {file_path}")
                continue
        except Exception as e:
            invalid_files.append(f"Path {i}: Cannot access file - {file_path}")
            continue
        
        # Check if file is readable
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                f.read(1)  # Try to read first byte
        except PermissionError:
            invalid_files.append(f"Path {i}: Permission denied - {file_path}")
            continue
        except Exception as e:
            invalid_files.append(f"Path {i}: Cannot read file - {file_path}")
            continue
        
        validated_paths.append(path)
    
    if not validated_paths:
        error_message = "No valid files found in the provided paths"
        if invalid_files:
            error_message += f"\nIssues found:\n" + "\n".join(invalid_files[:10])  # Show first 10 issues
            
        raise CodeScanException(
            code=ErrorCode.INVALID_INPUT,
            message=error_message,
            severity=ErrorSeverity.MEDIUM,
            component="agent",
            operation="validate_file_paths",
            recovery_suggestion="Kiểm tra các đường dẫn file có tồn tại, accessible và có quyền đọc",
            additional_data={"invalid_files": invalid_files, "total_files": len(file_paths)}
        )
    
    # Log warnings for invalid files if any
    if invalid_files:
        logger.warning(f"Skipped {len(invalid_files)} invalid files out of {len(file_paths)} total")
        for issue in invalid_files[:5]:  # Log first 5 issues
            logger.warning(f"  {issue}")
    
    return validated_paths


def format_scan_results(raw_result: Dict[str, Any], context: str = "", enhanced: bool = True) -> Dict[str, Any]:
    """Format scan results cho human-readable output với robust serialization và enhanced formatting"""
    try:
        if not isinstance(raw_result, dict):
            return {
                "status": "error",
                "error_message": "Invalid result format from scanner"
            }
        
        # Check for direct error
        if "error" in raw_result:
            return {
                "status": "error",
                "error_message": raw_result["error"]
            }
        
        # Use advanced extraction utility
        from .serialization_utils import extract_scan_results
        extraction_result = extract_scan_results(raw_result, context=f"format_results_{context}")
        
        if extraction_result["status"] != "success":
            return {
                "status": "error",
                "error_message": f"Failed to extract findings: {extraction_result.get('errors', 'unknown')}"
            }
        
        findings = extraction_result["findings"]
        findings_count = len(findings)
        
        if findings_count == 0:
            base_result = {
                "status": "success",
                "summary": f"✅ Không tìm thấy vấn đề bảo mật nào{' trong ' + context if context else ''}",
                "total_findings": 0,
                "detailed_results": [],
                "severity_breakdown": {}
            }
            
            # Apply enhanced formatting for no findings case
            if enhanced:
                from .output_formatter import format_enhanced_scan_results
                return format_enhanced_scan_results(base_result, scan_target=context)
            
            return base_result
        
        # Phân loại theo mức độ nghiêm trọng
        severity_counts = {}
        high_severity_findings = []
        
        for finding in findings:
            if isinstance(finding, dict):
                severity = finding.get("extra", {}).get("severity", "info").lower()
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
                
                # Collect high severity findings
                if severity in ["error", "warning"]:
                    file_path = finding.get("path", "unknown")
                    # Ensure we show full relative path from scan root
                    if file_path != "unknown" and not file_path.startswith("/"):
                        file_path = f"./{file_path}"
                    
                    high_severity_findings.append({
                        "rule_id": finding.get("check_id", "unknown"),
                        "message": finding.get("extra", {}).get("message", "No message"),
                        "severity": severity,
                        "file_path": file_path,  # Use more descriptive key
                        "line": finding.get("start", {}).get("line", "unknown"),
                        "absolute_path": finding.get("path", "unknown")  # Keep original for reference
                    })
        
        summary = f"🔍 Tìm thấy {findings_count} vấn đề{' trong ' + context if context else ''}"
        
        base_result = {
            "status": "success",
            "summary": summary,
            "total_findings": findings_count,
            "severity_breakdown": severity_counts,
            "high_severity_findings": high_severity_findings[:5],  # Top 5 critical issues
            "detailed_results": findings[:10],  # First 10 detailed results
            "note": f"Hiển thị top issues từ {findings_count} kết quả" if findings_count > 10 else None
        }
        
        # Apply enhanced formatting if requested
        if enhanced:
            from .output_formatter import format_enhanced_scan_results
            return format_enhanced_scan_results(base_result, scan_target=context)
        
        return base_result
        
    except Exception as e:
        logger.error(f"Error formatting scan results: {e}")
        return {
            "status": "error",
            "error_message": f"Failed to format results: {str(e)}",
            "raw_result": raw_result
        }


@handle_errors("agent", "scan_code_directory")  
def scan_code_directory(directory_path: str, config: Optional[str] = None, intelligent: bool = True) -> Dict[str, Any]:
    """
    Scan toàn bộ thư mục code để tìm lỗ hổng bảo mật với intelligent optimization
    
    Args:
        directory_path (str): Đường dẫn đến thư mục cần scan
        config (str, optional): Cấu hình Semgrep (ví dụ: 'auto', 'p/security-audit')
        intelligent (bool): Sử dụng intelligent scanning với workflow agents (mặc định: True)
        
    Returns:
        dict: Kết quả scan bao gồm các lỗ hổng tìm thấy
    """
    try:
        # Validate input
        validated_path = validate_directory_path(directory_path)
        
        # Intelligent scanning mode
        if intelligent:
            logger.info("Using intelligent scanning with ADK workflow agents")
            try:
                from .intelligent.scanner import intelligent_scan_code_directory
                result = intelligent_scan_code_directory(str(validated_path))
                
                # Add scan metadata
                result.update({
                    "scan_type": "intelligent_directory",
                    "scan_target": str(validated_path),
                    "intelligent_features": True
                })
                
                return result
                
            except Exception as e:
                logger.warning(f"Intelligent scanning failed, falling back to traditional: {e}")
                # Fall through to traditional scanning
        
        # Traditional scanning mode (fallback hoặc khi config được chỉ định)
        logger.info("Using traditional scanning mode")
        
        # Validate config if provided
        if config and not config.strip():
            config = None
        
        # Sử dụng context manager để ensure cleanup
        with get_semgrep_client() as client:
            result = client.scan_directory(str(validated_path), config)
            
            formatted_result = format_scan_results(
                result, 
                context=f"thư mục '{validated_path.name}'"
            )
            
            # Add metadata
            formatted_result.update({
                "scan_type": "traditional_directory",
                "scan_target": str(validated_path),
                "config_used": config or "default",
                "intelligent_features": False
            })
            
            return formatted_result
        
    except CodeScanException:
        # Re-raise CodeScanException as-is (will be handled by decorator)
        raise
    except SemgrepMCPError as e:
        # Convert legacy exception
        raise CodeScanException(
            code=ErrorCode.SCAN_FAILED,
            message=f"Scanner error: {str(e)}",
            severity=ErrorSeverity.HIGH,
            component="agent",
            operation="scan_code_directory",
            original_exception=e,
            recovery_suggestion="Kiểm tra server connection và thử lại"
        )
    except Exception as e:
        # Convert unexpected exceptions
        raise CodeScanException(
            code=ErrorCode.UNEXPECTED_ERROR,
            message=f"Unexpected error scanning directory: {str(e)}",
            severity=ErrorSeverity.MEDIUM,
            component="agent",
            operation="scan_code_directory",
            original_exception=e,
            additional_data={"directory_path": directory_path, "config": config}
        )


def scan_code_files(file_paths: List[str], config: Optional[str] = None, intelligent: bool = True) -> Dict[str, Any]:
    """
    Scan các file code cụ thể để tìm lỗ hổng bảo mật với intelligent workflow
    
    Args:
        file_paths (List[str]): Danh sách đường dẫn file cần scan
        config (str, optional): Cấu hình Semgrep
        intelligent (bool): Sử dụng intelligent workflow (mặc định: True)
        
    Returns:
        dict: Kết quả scan với intelligent enhancements
    """
    # Intelligent workflow mode
    if intelligent:
        try:
            from .intelligent.workflows import apply_intelligent_workflow
            
            @apply_intelligent_workflow("scan_code_files")
            def intelligent_scan_files(files, cfg=None):
                return _scan_code_files_traditional(files, cfg)
            
            return intelligent_scan_files(file_paths, config)
            
        except Exception as e:
            logger.warning(f"Intelligent workflow failed, falling back to traditional: {e}")
            # Fall through to traditional scanning
    
    # Traditional scanning mode
    return _scan_code_files_traditional(file_paths, config)


def _scan_code_files_traditional(file_paths: List[str], config: Optional[str] = None) -> Dict[str, Any]:
    """Traditional scan code files implementation"""
    try:
        # Validate input
        validated_paths = validate_file_paths(file_paths)
        
        # Use 'auto' as default config for maximum coverage
        if config is None:
            config = "auto"
            logger.info("Using default 'auto' config for maximum coverage")
        
        # Prepare code files
        code_files = []
        for path in validated_paths:
            try:
                # Check file size (skip very large files)
                if path.stat().st_size > 5 * 1024 * 1024:  # 5MB limit
                    logger.warning(f"Skipping large file: {path}")
                    continue
                
                content = path.read_text(encoding='utf-8', errors='ignore')
                code_files.append({
                    "filename": path.name,
                    "content": content
                })
            except Exception as e:
                logger.warning(f"Cannot read file {path}: {e}")
                continue
        
        if not code_files:
            return {
                "status": "error",
                "error_message": "No valid files could be read for scanning"
            }
        
        # Scan with context manager
        with get_semgrep_client() as client:
            result = client.scan_code_files(code_files, config)
            
            return {
                "status": "success",
                "files_scanned": len(code_files),
                **format_scan_results(result, context=f"{len(code_files)} files")
            }
        
    except (ValueError, FileNotFoundError) as e:
        logger.error(f"Input validation error: {e}")
        return {
            "status": "error",
            "error_message": str(e)
        }
    except SemgrepMCPError as e:
        logger.error(f"Semgrep MCP error: {e}")
        return {
            "status": "error",
            "error_message": f"Scanner error: {str(e)}"
        }
    except Exception as e:
        logger.error(f"Unexpected error scanning files: {e}")
        return {
            "status": "error",
            "error_message": f"Unexpected error: {str(e)}"
        }


def quick_security_check(code_content: str, language: str, intelligent: bool = True) -> Dict[str, Any]:
    """
    Thực hiện kiểm tra bảo mật nhanh với intelligent analysis
    
    Args:
        code_content (str): Nội dung code cần kiểm tra
        language (str): Ngôn ngữ lập trình (ví dụ: python, javascript, java)
        intelligent (bool): Sử dụng intelligent workflow (mặc định: True)
        
    Returns:
        dict: Kết quả kiểm tra bảo mật với intelligent enhancements
    """
    # Intelligent workflow mode
    if intelligent:
        try:
            from .intelligent.workflows import apply_intelligent_workflow
            
            @apply_intelligent_workflow("quick_security_check")
            def intelligent_quick_security_check(code, lang):
                return _quick_security_check_traditional(code, lang)
            
            return intelligent_quick_security_check(code_content, language)
            
        except Exception as e:
            logger.warning(f"Intelligent workflow failed, falling back to traditional: {e}")
            # Fall through to traditional checking
    
    # Traditional checking mode
    return _quick_security_check_traditional(code_content, language)


def _quick_security_check_traditional(code_content: str, language: str) -> Dict[str, Any]:
    """Traditional quick security check implementation"""
    try:
        # Validate input
        if not code_content or not code_content.strip():
            return {
                "status": "error",
                "error_message": "Code content cannot be empty"
            }
        
        if not language or not language.strip():
            return {
                "status": "error",
                "error_message": "Language must be specified"
            }
        
        language = language.lower().strip()
        
        # Map common language aliases
        language_mapping = {
            'js': 'javascript',
            'ts': 'typescript',
            'py': 'python',
            'cpp': 'c++',
            'csharp': 'c#',
            'cs': 'c#'
        }
        
        mapped_language = language_mapping.get(language, language)
        
        # Tạo file giả với extension phù hợp
        file_extensions = {
            'python': '.py',
            'javascript': '.js',
            'typescript': '.ts',
            'java': '.java',
            'c': '.c',
            'c++': '.cpp',
            'php': '.php',
            'ruby': '.rb',
            'go': '.go',
            'rust': '.rs',
            'swift': '.swift',
            'kotlin': '.kt',
            'scala': '.scala',
            'c#': '.cs'
        }
        
        extension = file_extensions.get(mapped_language, '.txt')
        filename = f"temp_code{extension}"
        
        code_files = [{
            "filename": filename,
            "content": code_content
        }]
        
        # Perform security check
        with get_semgrep_client() as client:
            result = client.security_check(code_files)
            
            formatted_result = format_scan_results(
                result, 
                context=f"đoạn code {mapped_language}"
            )
            
            # Add language info
            formatted_result["language"] = mapped_language
            formatted_result["original_language_input"] = language
            
            return formatted_result
        
    except SemgrepMCPError as e:
        logger.error(f"Semgrep MCP error: {e}")
        return {
            "status": "error",
            "error_message": f"Security check failed: {str(e)}"
        }
    except Exception as e:
        logger.error(f"Unexpected error in quick security check: {e}")
        return {
            "status": "error",
            "error_message": f"Unexpected error: {str(e)}"
        }


def scan_with_custom_rule(code_content: str, rule: str, language: str = "python", intelligent: bool = True) -> Dict[str, Any]:
    """
    Scan code với custom Semgrep rule và intelligent analysis
    
    Args:
        code_content (str): Nội dung code cần scan
        rule (str): Custom Semgrep rule (YAML format)
        language (str): Ngôn ngữ lập trình
        intelligent (bool): Sử dụng intelligent workflow (mặc định: True)
        
    Returns:
        dict: Kết quả scan với intelligent enhancements
    """
    # Intelligent workflow mode
    if intelligent:
        try:
            from .intelligent.workflows import apply_intelligent_workflow
            
            @apply_intelligent_workflow("scan_with_custom_rule")
            def intelligent_scan_with_custom_rule(code, r, lang):
                return _scan_with_custom_rule_traditional(code, r, lang)
            
            return intelligent_scan_with_custom_rule(code_content, rule, language)
            
        except Exception as e:
            logger.warning(f"Intelligent workflow failed, falling back to traditional: {e}")
            # Fall through to traditional scanning
    
    # Traditional scanning mode
    return _scan_with_custom_rule_traditional(code_content, rule, language)


def _scan_with_custom_rule_traditional(code_content: str, rule: str, language: str = "python") -> Dict[str, Any]:
    """Traditional custom rule scan implementation"""
    try:
        # Validate input
        if not code_content or not code_content.strip():
            return {
                "status": "error",
                "error_message": "Code content cannot be empty"
            }
        
        if not rule or not rule.strip():
            return {
                "status": "error",
                "error_message": "Custom rule cannot be empty"
            }
        
        # Basic YAML validation
        if not rule.strip().startswith(('rules:', '- id:')):
            return {
                "status": "error",
                "error_message": "Rule must be valid YAML starting with 'rules:' or '- id:'"
            }
        
        language = language.lower().strip()
        
        # Map file extension
        file_extensions = {
            'python': '.py',
            'javascript': '.js',
            'typescript': '.ts',
            'java': '.java',
            'c': '.c',
            'cpp': '.cpp',
            'php': '.php',
            'ruby': '.rb',
            'go': '.go'
        }
        
        extension = file_extensions.get(language, '.py')
        filename = f"custom_scan{extension}"
        
        code_files = [{
            "filename": filename,
            "content": code_content
        }]
        
        # Scan with custom rule
        with get_semgrep_client() as client:
            result = client.scan_with_custom_rule(code_files, rule)
            
            formatted_result = format_scan_results(
                result,
                context=f"custom rule scan ({language})"
            )
            
            formatted_result["custom_rule_used"] = True
            formatted_result["language"] = language
            
            return formatted_result
        
    except SemgrepMCPError as e:
        logger.error(f"Custom rule scan error: {e}")
        return {
            "status": "error",
            "error_message": f"Custom rule scan failed: {str(e)}"
        }
    except Exception as e:
        logger.error(f"Unexpected error in custom rule scan: {e}")
        return {
            "status": "error",
            "error_message": f"Unexpected error: {str(e)}"
        }


def get_supported_languages(intelligent: bool = True) -> Dict[str, Any]:
    """
    Lấy danh sách ngôn ngữ lập trình được hỗ trợ với intelligent enhancements
    
    Args:
        intelligent (bool): Sử dụng intelligent workflow (mặc định: True)
    
    Returns:
        dict: Danh sách ngôn ngữ và thông tin liên quan với intelligent features
    """
    # Intelligent workflow mode
    if intelligent:
        try:
            from .intelligent.workflows import apply_intelligent_workflow
            
            @apply_intelligent_workflow("get_supported_languages")
            def intelligent_get_supported_languages():
                return _get_supported_languages_traditional()
            
            return intelligent_get_supported_languages()
            
        except Exception as e:
            logger.warning(f"Intelligent workflow failed, falling back to traditional: {e}")
            # Fall through to traditional mode
    
    # Traditional mode
    return _get_supported_languages_traditional()


def _get_supported_languages_traditional() -> Dict[str, Any]:
    """Traditional get supported languages implementation"""
    try:
        with get_semgrep_client() as client:
            languages = client.get_supported_languages()
            
            if isinstance(languages, list) and languages:
                return {
                    "status": "success",
                    "total_languages": len(languages),
                    "supported_languages": sorted(languages),
                    "popular_languages": [
                        lang for lang in ["python", "javascript", "typescript", "java", "go", "php", "ruby", "c", "cpp"]
                        if lang in languages
                    ],
                    "note": "Đây là danh sách ngôn ngữ được Semgrep hỗ trợ cho static analysis"
                }
            else:
                return {
                    "status": "warning",
                    "message": "Could not retrieve supported languages list",
                    "supported_languages": []
                }
        
    except SemgrepMCPError as e:
        logger.error(f"Error getting supported languages: {e}")
        return {
            "status": "error",
            "error_message": f"Failed to get supported languages: {str(e)}"
        }
    except Exception as e:
        logger.error(f"Unexpected error getting supported languages: {e}")
        return {
            "status": "error",
            "error_message": f"Unexpected error: {str(e)}"
        }


def analyze_code_structure(code_content: str, language: str, intelligent: bool = True) -> Dict[str, Any]:
    """
    Phân tích cấu trúc code bằng Abstract Syntax Tree với intelligent enhancements
    
    Args:
        code_content (str): Nội dung code cần phân tích
        language (str): Ngôn ngữ lập trình
        intelligent (bool): Sử dụng intelligent workflow (mặc định: True)
        
    Returns:
        dict: Cấu trúc AST và thông tin phân tích với intelligent features
    """
    # Intelligent workflow mode
    if intelligent:
        try:
            from .intelligent.workflows import apply_intelligent_workflow
            
            @apply_intelligent_workflow("analyze_code_structure")
            def intelligent_analyze_code_structure(code, lang):
                return _analyze_code_structure_traditional(code, lang)
            
            return intelligent_analyze_code_structure(code_content, language)
            
        except Exception as e:
            logger.warning(f"Intelligent workflow failed, falling back to traditional: {e}")
            # Fall through to traditional analysis
    
    # Traditional analysis mode
    return _analyze_code_structure_traditional(code_content, language)


def _analyze_code_structure_traditional(code_content: str, language: str) -> Dict[str, Any]:
    """Traditional code structure analysis implementation"""
    try:
        # Validate input
        if not code_content or not code_content.strip():
            return {
                "status": "error",
                "error_message": "Code content cannot be empty"
            }
        
        if not language or not language.strip():
            return {
                "status": "error",
                "error_message": "Language must be specified"
            }
        
        language = language.lower().strip()
        
        # Get AST
        with get_semgrep_client() as client:
            result = client.get_abstract_syntax_tree(code_content, language)
            
            if "error" in result:
                return {
                    "status": "error",
                    "error_message": f"AST analysis failed: {result['error']}"
                }
            
            return {
                "status": "success",
                "language": language,
                "ast_analysis": result,
                "note": "Abstract Syntax Tree analysis completed"
            }
        
    except SemgrepMCPError as e:
        logger.error(f"AST analysis error: {e}")
        return {
            "status": "error",
            "error_message": f"AST analysis failed: {str(e)}"
        }
    except Exception as e:
        logger.error(f"Unexpected error in AST analysis: {e}")
        return {
            "status": "error",
            "error_message": f"Unexpected error: {str(e)}"
        }


def get_semgrep_rule_schema(intelligent: bool = True) -> Dict[str, Any]:
    """
    Lấy schema định nghĩa cho Semgrep rules với intelligent enhancements
    
    Args:
        intelligent (bool): Sử dụng intelligent workflow (mặc định: True)
    
    Returns:
        dict: Schema và documentation cho việc tạo custom rules với intelligent features
    """
    # Intelligent workflow mode
    if intelligent:
        try:
            from .intelligent.workflows import apply_intelligent_workflow
            
            @apply_intelligent_workflow("get_semgrep_rule_schema")
            def intelligent_get_semgrep_rule_schema():
                return _get_semgrep_rule_schema_traditional()
            
            return intelligent_get_semgrep_rule_schema()
            
        except Exception as e:
            logger.warning(f"Intelligent workflow failed, falling back to traditional: {e}")
            # Fall through to traditional mode
    
    # Traditional mode
    return _get_semgrep_rule_schema_traditional()


def _get_semgrep_rule_schema_traditional() -> Dict[str, Any]:
    """Traditional get semgrep rule schema implementation"""
    try:
        with get_semgrep_client() as client:
            result = client.get_rule_schema()
            
            if "error" in result:
                return {
                    "status": "error",
                    "error_message": f"Failed to get rule schema: {result['error']}"
                }
            
            return {
                "status": "success",
                "rule_schema": result,
                "note": "Semgrep rule schema for creating custom rules"
            }
        
    except SemgrepMCPError as e:
        logger.error(f"Rule schema error: {e}")
        return {
            "status": "error",
            "error_message": f"Failed to get rule schema: {str(e)}"
        }
    except Exception as e:
        logger.error(f"Unexpected error getting rule schema: {e}")
        return {
            "status": "error",
            "error_message": f"Unexpected error: {str(e)}"
        }


@handle_errors("agent", "intelligent_project_analysis")
def intelligent_project_analysis(directory_path: str) -> Dict[str, Any]:
    """
    Analyze project with intelligent workflow để xác định scan strategy tối ưu
    
    Args:
        directory_path (str): Đường dẫn thư mục project cần analyze
        
    Returns:
        dict: Kết quả phân tích và recommendations
    """
    try:
        # Validate input
        validated_path = validate_directory_path(directory_path)
        
        # Use intelligent scanner for analysis
        try:
            from .intelligent.scanner import IntelligentCodeScanner
            scanner = IntelligentCodeScanner()
            
            # Run rule analysis
            rule_results = scanner.rule_analysis_agent.analyze_project_rules(str(validated_path))
            
            # If rule analysis succeeded, run pattern analysis
            if rule_results.get("status") == "success":
                languages = rule_results.get("analysis", {}).get("languages_detected", [])
                pattern_results = scanner.code_pattern_agent.analyze_code_patterns(
                    str(validated_path), languages
                )
            else:
                pattern_results = {"status": "error", "error": "Rule analysis failed"}
            
            # Generate recommendations
            recommendations = _generate_intelligent_recommendations(
                rule_results,
                pattern_results
            )
            
            # Determine optimal strategy
            optimal_strategy = _determine_optimal_strategy(rule_results, pattern_results)
            
            return {
                "status": "success",
                "rule_analysis": rule_results,
                "pattern_analysis": pattern_results,
                "recommendations": recommendations,
                "optimal_scan_strategy": optimal_strategy
            }
            
        except Exception as e:
            logger.error(f"Intelligent project analysis failed: {e}")
            raise CodeScanException(
                code=ErrorCode.INTELLIGENT_ANALYSIS_FAILED,
                message=f"Intelligent project analysis failed: {str(e)}",
                severity=ErrorSeverity.MEDIUM,
                component="agent",
                operation="intelligent_project_analysis",
                original_exception=e
            )
        
    except CodeScanException:
        raise
    except Exception as e:
        raise CodeScanException(
            code=ErrorCode.UNEXPECTED_ERROR,
            message=f"Unexpected error analyzing project: {str(e)}",
            severity=ErrorSeverity.MEDIUM,
            component="agent",
            operation="intelligent_project_analysis",
            original_exception=e,
            additional_data={"directory_path": directory_path}
        )


def _generate_intelligent_recommendations(rule_analysis: Dict, pattern_analysis: Dict) -> List[str]:
    """Generate recommendations based on intelligent analysis"""
    recommendations = []
    
    # Rule-based recommendations
    if rule_analysis.get('status') == 'success':
        analysis = rule_analysis.get('analysis', {})
        languages = analysis.get('languages_detected', [])
        frameworks = analysis.get('frameworks_detected', [])
        rules = analysis.get('recommended_rules', [])
        
        if len(languages) > 1:
            recommendations.append(f"Multi-language project detected ({len(languages)} languages). Consider using language-specific scan configurations.")
        
        if frameworks:
            recommendations.append(f"Framework-specific security rules recommended for: {', '.join(frameworks)}")
        
        if len(rules) > 5:
            recommendations.append("Many security rules applicable. Consider prioritizing based on project risk assessment.")
    
    # Pattern-based recommendations  
    if pattern_analysis.get('status') == 'success':
        pattern_data = pattern_analysis.get('pattern_analysis', {})
        risk_patterns = pattern_data.get('risk_patterns', [])
        scan_priorities = pattern_data.get('scan_priorities', {})
        
        high_risk = [p for p in risk_patterns if p.get('severity') == 'high']
        if high_risk:
            recommendations.append(f"High-risk security patterns detected in {len(high_risk)} categories. Immediate security review recommended.")
        
        priority_level = scan_priorities.get('priority_level', 'medium')
        if priority_level == 'high':
            recommendations.append("High-priority security scan recommended due to detected risk factors.")
        elif priority_level == 'low':
            recommendations.append("Quick security scan may be sufficient for this project profile.")
    
    # Add general intelligent scanning recommendation
    recommendations.append("Use intelligent scanning mode for optimized rule selection and better performance.")
    
    return recommendations[:8]  # Limit to top 8 recommendations


def _determine_optimal_strategy(rule_analysis: Dict, pattern_analysis: Dict) -> Dict[str, Any]:
    """Determine optimal scanning strategy based on analysis"""
    strategy = {
        "recommended_approach": "intelligent_scan",
        "confidence_level": "medium"
    }
    
    # Analyze confidence based on successful analysis steps
    success_count = 0
    if rule_analysis.get('status') == 'success':
        success_count += 1
        strategy["rule_optimization"] = "available"
    
    if pattern_analysis.get('status') == 'success':
        success_count += 1
        strategy["pattern_optimization"] = "available"
        
        # Extract priority information
        pattern_data = pattern_analysis.get('pattern_analysis', {})
        scan_priorities = pattern_data.get('scan_priorities', {})
        priority_level = scan_priorities.get('priority_level', 'medium')
        
        strategy["scan_priority"] = priority_level
        strategy["recommended_scan_approach"] = scan_priorities.get('recommended_scan_approach', 'targeted_scan')
    
    # Set confidence level
    if success_count == 2:
        strategy["confidence_level"] = "high"
    elif success_count == 1:
        strategy["confidence_level"] = "medium"
    else:
        strategy["confidence_level"] = "low"
        strategy["recommended_approach"] = "traditional_scan"
    
    return strategy


def analyze_project_architecture(directory_path: str, intelligent: bool = True) -> Dict[str, Any]:
    """
    Phân tích kiến trúc và cấu trúc bảo mật với intelligent enhancements
    
    Args:
        directory_path (str): Đường dẫn đến thư mục project
        intelligent (bool): Sử dụng intelligent workflow (mặc định: True)
        
    Returns:
        dict: Phân tích kiến trúc, recommendations bảo mật và best practices với intelligent features
    """
    # Intelligent workflow mode
    if intelligent:
        try:
            from .intelligent.workflows import apply_intelligent_workflow
            
            @apply_intelligent_workflow("analyze_project_architecture")
            def intelligent_analyze_project_architecture(dir):
                return _analyze_project_architecture_traditional(dir)
            
            return intelligent_analyze_project_architecture(directory_path)
            
        except Exception as e:
            logger.warning(f"Intelligent workflow failed, falling back to traditional: {e}")
            # Fall through to traditional analysis
    
    # Traditional analysis mode
    return _analyze_project_architecture_traditional(directory_path)


def _analyze_project_architecture_traditional(directory_path: str) -> Dict[str, Any]:
    """Traditional project architecture analysis implementation"""
    try:
        # Validate directory path
        validated_path = validate_directory_path(directory_path)
        
        # Scan toàn bộ project để phát hiện vulnerabilities
        scan_result = scan_code_directory(directory_path)
        
        # Check if scan_result is error response
        if not isinstance(scan_result, dict) or scan_result.get("status") == "error":
            return {
                "status": "error", 
                "error_message": f"Failed to scan project: {scan_result.get('error_message', 'Unknown error') if isinstance(scan_result, dict) else str(scan_result)}"
            }
        
        # Phân tích cấu trúc project
        project_analysis = {
            "project_path": str(validated_path),
            "total_files_analyzed": 0,
            "languages_detected": [],
            "frameworks_detected": [],
            "architecture_patterns": [],
            "security_recommendations": [],
            "best_practices": []
        }
        
        # Extract information from scan results
        detailed_results = scan_result.get("detailed_results", [])
        high_severity_findings = scan_result.get("high_severity_findings", [])
        
        # Detect languages from actual project file structure (not just findings)
        languages = set()
        frameworks = set()
        
        try:
            # Scan actual file structure for comprehensive language detection
            for file_path in validated_path.rglob("*"):
                if file_path.is_file():
                    file_ext = file_path.suffix.lower()
                    relative_path = str(file_path.relative_to(validated_path))
                    
                    # Language detection from file extensions
                    if file_ext == ".py":
                        languages.add("Python")
                    elif file_ext in [".js", ".jsx"]:
                        languages.add("JavaScript") 
                    elif file_ext in [".ts", ".tsx"]:
                        languages.add("TypeScript")
                    elif file_ext == ".java":
                        languages.add("Java")
                    elif file_ext in [".php"]:
                        languages.add("PHP")
                    elif file_ext in [".go"]:
                        languages.add("Go")
                    elif file_ext in [".rb"]:
                        languages.add("Ruby")
                    elif file_ext in [".cs"]:
                        languages.add("C#")
                    elif file_ext in [".html", ".htm"]:
                        languages.add("HTML")
                    elif file_ext in [".css"]:
                        languages.add("CSS")
                    elif file_ext in [".sql"]:
                        languages.add("SQL")
                    elif file_ext in [".c"]:
                        languages.add("C")
                    elif file_ext in [".cpp", ".cc", ".cxx"]:
                        languages.add("C++")
                    elif file_ext in [".rs"]:
                        languages.add("Rust")
                    elif file_ext in [".swift"]:
                        languages.add("Swift")
                    elif file_ext in [".kt"]:
                        languages.add("Kotlin")
                    elif file_ext in [".scala"]:
                        languages.add("Scala")
                    elif file_ext in [".sh", ".bash"]:
                        languages.add("Shell")
                    elif file_ext in [".yml", ".yaml"]:
                        languages.add("YAML")
                    elif file_ext in [".json"]:
                        languages.add("JSON")
                    elif file_ext in [".xml"]:
                        languages.add("XML")
                    elif file_ext in [".md"]:
                        languages.add("Markdown")
                    
                    # Framework detection từ file paths và structure
                    relative_path_lower = relative_path.lower()
                    file_name = file_path.name.lower()
                    
                    # Django detection
                    if any(indicator in relative_path_lower for indicator in [
                        "manage.py", "settings.py", "urls.py", "models.py", "views.py", 
                        "forms.py", "admin.py", "/migrations/", "wsgi.py", "asgi.py"
                    ]):
                        frameworks.add("Django")
                    
                    # Flask detection
                    elif any(indicator in file_name for indicator in ["app.py", "flask"]) or "flask" in relative_path_lower:
                        frameworks.add("Flask")
                    
                    # React/Node.js detection
                    elif any(indicator in file_name for indicator in [
                        "package.json", "package-lock.json", "yarn.lock", "webpack.config.js"
                    ]) or "node_modules" in relative_path_lower:
                        frameworks.add("React/Node.js")
                    
                    # Spring detection
                    elif any(indicator in relative_path_lower for indicator in [
                        "pom.xml", "build.gradle", "/src/main/java/", "application.properties"
                    ]):
                        frameworks.add("Spring")
                    
                    # Laravel detection
                    elif any(indicator in file_name for indicator in [
                        "composer.json", "artisan"
                    ]) or "/vendor/" in relative_path_lower:
                        frameworks.add("Laravel")
                    
                    # Docker detection
                    elif file_name in ["dockerfile", "docker-compose.yml", "docker-compose.yaml"]:
                        frameworks.add("Docker")
                    
                    # Web Templates detection
                    elif "/templates/" in relative_path_lower and file_ext in [".html", ".htm"]:
                        frameworks.add("Web Templates")
                    
                    # Database detection
                    elif file_ext in [".sql"] or "migrations" in relative_path_lower:
                        frameworks.add("Database")
                        
        except Exception as e:
            logger.warning(f"Error scanning project structure: {e}")
            # Fallback: detect from findings only
            all_findings = detailed_results + high_severity_findings
            for finding in all_findings:
                if isinstance(finding, dict):
                    file_path = finding.get("path") or finding.get("file") or ""
                    if file_path:
                        file_ext = Path(file_path).suffix.lower()
                        if file_ext == ".py":
                            languages.add("Python")
                        elif file_ext in [".html", ".htm"]:
                            languages.add("HTML")
                        # Add other basic detections...
        
        project_analysis["languages_detected"] = list(languages)
        project_analysis["frameworks_detected"] = list(frameworks)
        
        # Count total code files in project
        try:
            code_files_count = 0
            code_extensions = {'.py', '.js', '.jsx', '.ts', '.tsx', '.java', '.php', '.go', '.rb', 
                             '.cs', '.html', '.htm', '.css', '.sql', '.c', '.cpp', '.cc', '.cxx', 
                             '.rs', '.swift', '.kt', '.scala'}
            
            for file_path in validated_path.rglob("*"):
                if file_path.is_file() and file_path.suffix.lower() in code_extensions:
                    code_files_count += 1
                    
            project_analysis["total_files_analyzed"] = code_files_count
        except Exception as e:
            logger.warning(f"Error counting files: {e}")
            project_analysis["total_files_analyzed"] = scan_result.get("total_findings", 0)
        
        # Security Architecture Analysis dựa trên scan results  
        security_issues = high_severity_findings + detailed_results
        high_critical_issues = [
            issue for issue in high_severity_findings 
            if issue.get("severity", "").lower() in ["error", "warning"]
        ]
        
        # Generate architecture recommendations based on findings
        recommendations = []
        
        # Check for specific vulnerability patterns
        rule_ids = []
        for issue in security_issues:
            if isinstance(issue, dict):
                rule_id = issue.get("rule_id", issue.get("check_id", "")).lower()
                rule_ids.append(rule_id)
        
        # Check for SQL injection patterns
        if any("sql" in rule_id for rule_id in rule_ids):
            recommendations.append({
                "category": "Database Security",
                "issue": "SQL Injection vulnerabilities detected",
                "recommendation": "Implement parameterized queries, use ORM properly, validate input",
                "priority": "HIGH"
            })
        
        # Check for command injection patterns
        if any("command" in rule_id for rule_id in rule_ids):
            recommendations.append({
                "category": "Command Injection",
                "issue": "Command injection vulnerabilities found",
                "recommendation": "Avoid shell execution, sanitize inputs, use subprocess safely",
                "priority": "CRITICAL"
            })
        
        # Check for hardcoded secrets
        if any("hardcoded" in rule_id or "secret" in rule_id for rule_id in rule_ids):
            recommendations.append({
                "category": "Secret Management", 
                "issue": "Hardcoded secrets detected",
                "recommendation": "Use environment variables, secret management services (HashiCorp Vault, AWS Secrets Manager)",
                "priority": "HIGH"
            })
        
        # Check for XSS vulnerabilities
        if any("xss" in rule_id for rule_id in rule_ids):
            recommendations.append({
                "category": "Input Validation",
                "issue": "XSS vulnerabilities found",
                "recommendation": "Implement proper input validation, output encoding, CSP headers",
                "priority": "HIGH"
            })
        
        # Check for CSRF vulnerabilities (specific to detected issues)
        if any("csrf" in rule_id for rule_id in rule_ids):
            recommendations.append({
                "category": "CSRF Protection",
                "issue": "CSRF protection vulnerabilities detected",
                "recommendation": "Implement CSRF tokens in all forms, use Django's {% csrf_token %} tag",
                "priority": "HIGH"
            })
        
        # Check for missing integrity attributes
        if any("integrity" in rule_id for rule_id in rule_ids):
            recommendations.append({
                "category": "Subresource Integrity",
                "issue": "Missing integrity attributes for external resources",
                "recommendation": "Add integrity attributes to external scripts and stylesheets to prevent CDN-based attacks",
                "priority": "MEDIUM"
            })
        
        # Check for Django-specific issues
        if any("django" in rule_id for rule_id in rule_ids):
            recommendations.append({
                "category": "Django Security",
                "issue": "Django-specific security issues detected",
                "recommendation": "Follow Django security best practices, enable security middleware, use built-in protections",
                "priority": "HIGH"
            })
        
        # General best practices based on detected languages/frameworks
        best_practices = []
        
        if "Python" in project_analysis["languages_detected"]:
            best_practices.extend([
                "Use virtual environments for dependency isolation",
                "Keep dependencies updated with tools like pip-audit",
                "Follow PEP 8 coding standards",
                "Use type hints for better code quality"
            ])
        
        if "Django" in project_analysis.get("frameworks_detected", []):
            best_practices.extend([
                "Enable Django security middleware",
                "Use Django's built-in CSRF protection", 
                "Implement proper authentication and authorization",
                "Configure secure settings (DEBUG=False, secure headers)"
            ])
        
        if "JavaScript" in project_analysis["languages_detected"]:
            best_practices.extend([
                "Use ESLint for code quality checking",
                "Audit npm packages regularly with npm audit",
                "Implement Content Security Policy (CSP)",
                "Use HTTPS only for production"
            ])
        
        # Add general recommendations
        best_practices.extend([
            "Implement comprehensive logging and monitoring",
            "Regular security code reviews",
            "Use static analysis tools (like this Semgrep scanner)",
            "Implement automated testing for security",
            "Follow OWASP security guidelines",
            "Use secure coding practices"
        ])
        
        # Compile final analysis
        project_analysis.update({
            "security_summary": {
                "total_issues": scan_result.get("total_findings", 0),
                "high_critical_issues": len(high_critical_issues),
                "issue_breakdown": scan_result.get("severity_breakdown", {}),
                "scan_status": scan_result.get("status", "unknown")
            },
            "security_recommendations": recommendations,
            "best_practices": best_practices[:12],  # Top 12 recommendations
            "detailed_findings": security_issues[:15] if security_issues else []  # Top 15 most critical findings
        })
        
        return {
            "status": "success",
            "project_architecture_analysis": project_analysis,
            "note": "Comprehensive project architecture and security analysis completed"
        }
        
    except CodeScanException as e:
        logger.error(f"Project architecture analysis error: {e}")
        return create_error_response(e)
    except Exception as e:
        logger.error(f"Unexpected error in project architecture analysis: {e}")
        return {
            "status": "error",
            "error_message": f"Unexpected error: {str(e)}"
        }


@handle_errors("agent", "scan_for_secrets")
def scan_for_secrets(file_paths: List[str], config: Optional[str] = None, intelligent: bool = True) -> Dict[str, Any]:
    """
    Scan files để phát hiện secrets và credentials bị hardcode
    
    Args:
        file_paths: Danh sách đường dẫn files cần scan
        config: Cấu hình Semgrep tùy chỉnh cho secrets
        intelligent: Có sử dụng intelligent analysis không
        
    Returns:
        Kết quả scan với phân tích secrets chi tiết
    """
    try:
        # Validate file paths
        validated_paths = validate_file_paths(file_paths)
        
        # Prepare code files cho Semgrep
        code_files = []
        for file_path in validated_paths:
            try:
                content = file_path.read_text(encoding='utf-8', errors='ignore')
                code_files.append({
                    "filename": str(file_path),
                    "content": content
                })
            except Exception as e:
                logger.warning(f"Cannot read file {file_path}: {e}")
                continue
        
        if not code_files:
            return create_error_response(CodeScanException(
                code=ErrorCode.INVALID_INPUT,
                message="No readable files found",
                severity=ErrorSeverity.MEDIUM,
                component="agent",
                operation="scan_for_secrets"
            ))
        
        # Get Semgrep client và scan
        client = get_semgrep_client()
        client.start_server()
        
        try:
            # Sử dụng secrets-specific scanning
            raw_result = client.scan_for_secrets(code_files, config)
            
            # Format results
            formatted_result = format_scan_results(
                raw_result, 
                context=f"Secrets scan for {len(code_files)} files"
            )
            
            # Add secrets-specific metadata
            if "secrets_summary" in raw_result:
                formatted_result["secrets_analysis"] = raw_result["secrets_summary"]
                
            formatted_result["scan_type"] = "secrets_detection"
            formatted_result["files_scanned"] = len(code_files)
            
            return formatted_result
            
        finally:
            client.stop_server()
            
    except CodeScanException as e:
        logger.error(f"Secrets scan error: {e}")
        return create_error_response(e)
    except Exception as e:
        logger.error(f"Unexpected error in secrets scan: {e}")
        return {
            "status": "error",
            "error_message": f"Unexpected error: {str(e)}"
        }


@handle_errors("agent", "scan_android_project")  
def scan_android_project(directory_path: str, config: Optional[str] = None, intelligent: bool = True) -> Dict[str, Any]:
    """
    Scan Android project để phát hiện lỗ hổng bảo mật mobile-specific
    
    Args:
        directory_path: Đường dẫn thư mục Android project
        config: Cấu hình Semgrep tùy chỉnh cho Android
        intelligent: Có sử dụng intelligent analysis không
        
    Returns:
        Kết quả scan với phân tích Android security chi tiết
    """
    try:
        # Validate directory  
        validated_path = validate_directory_path(directory_path)
        
        # Get Semgrep client và scan
        client = get_semgrep_client()
        client.start_server()
        
        try:
            # Sử dụng Android-specific scanning từ client
            raw_result = client.scan_android_project([], config)  # Empty list sẽ được handle bởi scan_directory
            
            # Nếu không có Android files, fallback sang directory scan với Android rules
            if raw_result.get("status") == "warning":
                raw_result = client.scan_directory(str(validated_path), config or "r/java.android r/kotlin.android")
                
                # Post-process để add Android context
                if raw_result.get("status") == "success":
                    raw_result = client._enhance_android_results(raw_result, raw_result.get("total_findings", 0))
            
            # Format results
            formatted_result = format_scan_results(
                raw_result, 
                context=f"Android security scan for {directory_path}"
            )
            
            # Add Android-specific metadata
            if "android_summary" in raw_result:
                formatted_result["android_analysis"] = raw_result["android_summary"]
                
            formatted_result["scan_type"] = "android_security"
            formatted_result["project_path"] = str(validated_path)
            
            return formatted_result
            
        finally:
            client.stop_server()
            
    except CodeScanException as e:
        logger.error(f"Android scan error: {e}")
        return create_error_response(e)
    except Exception as e:
        logger.error(f"Unexpected error in Android scan: {e}")
        return {
            "status": "error",
            "error_message": f"Unexpected error: {str(e)}"
        }


@handle_errors("agent", "scan_flutter_project")
def scan_flutter_project(directory_path: str, config: Optional[str] = None, intelligent: bool = True) -> Dict[str, Any]:
    """
    Scan Flutter project để phát hiện lỗ hổng bảo mật Flutter/Dart
    
    Args:
        directory_path: Đường dẫn thư mục Flutter project
        config: Cấu hình Semgrep tùy chỉnh cho Flutter
        intelligent: Có sử dụng intelligent analysis không
        
    Returns:
        Kết quả scan với phân tích Flutter security chi tiết
    """
    try:
        # Validate directory
        validated_path = validate_directory_path(directory_path)
        
        # Get Semgrep client và scan
        client = get_semgrep_client()
        client.start_server()
        
        try:
            # Sử dụng Flutter-specific scanning từ client
            raw_result = client.scan_flutter_project([], config)  # Empty list sẽ được handle bởi scan_directory
            
            # Nếu không có Flutter files, fallback sang directory scan với Dart rules
            if raw_result.get("status") == "warning":
                raw_result = client.scan_directory(str(validated_path), config or "r/dart.flutter")
                
                # Post-process để add Flutter context
                if raw_result.get("status") == "success":
                    raw_result = client._enhance_flutter_results(raw_result, raw_result.get("total_findings", 0))
            
            # Format results
            formatted_result = format_scan_results(
                raw_result, 
                context=f"Flutter security scan for {directory_path}"
            )
            
            # Add Flutter-specific metadata
            if "flutter_summary" in raw_result:
                formatted_result["flutter_analysis"] = raw_result["flutter_summary"]
                
            formatted_result["scan_type"] = "flutter_security"
            formatted_result["project_path"] = str(validated_path)
            
            return formatted_result
            
        finally:
            client.stop_server()
            
    except CodeScanException as e:
        logger.error(f"Flutter scan error: {e}")
        return create_error_response(e)
    except Exception as e:
        logger.error(f"Unexpected error in Flutter scan: {e}")
        return {
            "status": "error",
            "error_message": f"Unexpected error: {str(e)}"
        }


# Định nghĩa root agent với ADK
root_agent = ADKAgent(
    name="code_scan_agent",
    model="gemini-2.0-flash",
    description=(
        "Agent chuyên về scan code để tìm lỗ hổng bảo mật sử dụng Semgrep. "
        "Có thể scan thư mục, file cụ thể, phân tích kiến trúc project, hoặc đoạn code với các rule tùy chỉnh."
    ),
    instruction=(
        "Bạn là một chuyên gia bảo mật code có thể giúp scan và phân tích code để tìm các lỗ hổng bảo mật. "
        "Bạn sử dụng Semgrep - một công cụ static analysis mạnh mẽ để phát hiện:\n"
        "- Lỗ hổng bảo mật (SQL injection, XSS, etc.)\n"
        "- Secrets và credentials bị hardcode\n"
        "- Code smells và bad practices\n"
        "- Compliance violations\n"
        "- Custom security rules\n"
        "- Lỗ hổng bảo mật mobile/Android/Flutter\n\n"
        "CHỨC NĂNG CHÍNH:\n"
        "1. scan_code_directory(): Scan toàn bộ thư mục/project\n"
        "2. scan_code_files(): Scan danh sách files cụ thể\n"
        "3. analyze_project_architecture(): Phân tích kiến trúc và đưa ra recommendations bảo mật cho toàn bộ project\n"
        "4. analyze_code_structure(): Phân tích AST của một file đơn lẻ\n"
        "5. quick_security_check(): Check nhanh đoạn code snippet\n"
        "6. scan_with_custom_rule(): Scan với custom rule\n"
        "7. scan_for_secrets(): Phát hiện secrets, API keys, passwords hardcode\n"
        "8. scan_android_project(): Scan bảo mật cho Android project (Java/Kotlin)\n"
        "9. scan_flutter_project(): Scan bảo mật cho Flutter project (Dart)\n\n"
        "CHỨC NĂNG NÂNG CAO - SECRETS DETECTION:\n"
        "- Phát hiện API keys, passwords, tokens bị hardcode\n"
        "- Phân loại loại secrets (database, API, private keys)\n"
        "- Đánh giá mức độ rủi ro cho từng secret\n"
        "- Đưa ra recommendations để secure secrets\n\n"
        "CHỨC NĂNG NÂNG CAO - MOBILE SECURITY:\n"
        "- Android: Scan Java/Kotlin, XML manifests, Gradle configs\n"
        "- Flutter: Scan Dart code, pubspec.yaml, platform channels\n"
        "- Phát hiện lỗ hổng mobile-specific: permissions, intents, crypto\n"
        "- Phân tích security configurations cho mobile\n\n"
        "NGÔN NGỮ VÀ FRAMEWORK HỖ TRỢ:\n"
        "- Web: Python, JavaScript/TypeScript, Java, C/C++, PHP, Ruby, Go\n"
        "- Mobile: Kotlin, Dart/Flutter, Java Android, Swift (iOS)\n"
        "- Config: XML, YAML, JSON, Gradle, Properties\n"
        "- Infrastructure: Terraform, Docker, Shell scripts\n\n"
        "KHI NGƯỜI DÙNG YÊU CẦU PHÂN TÍCH PROJECT/ARCHITECTURE:\n"
        "- Sử dụng analyze_project_architecture() cho toàn bộ project\n"
        "- Sử dụng analyze_code_structure() cho file đơn lẻ\n"
        "- Đưa ra recommendations về kiến trúc bảo mật, best practices\n\n"
        "KHI NGƯỜI DÙNG YÊU CẦU SCAN SECRETS:\n"
        "- Sử dụng scan_for_secrets() để tìm hardcoded credentials\n"
        "- Phân tích entropy và patterns của potential secrets\n"
        "- Đưa ra recommendations về secret management\n\n"
        "KHI NGƯỜI DÙNG YÊU CẦU SCAN MOBILE/ANDROID:\n"
        "- Sử dụng scan_android_project() cho Android projects\n"
        "- Sử dụng scan_flutter_project() cho Flutter projects\n"
        "- Phân tích mobile-specific security issues\n\n"
        "Khi trả lời, hãy:\n"
        "1. Tóm tắt kết quả scan một cách rõ ràng\n"
        "2. Ưu tiên các vấn đề theo mức độ nghiêm trọng\n"
        "3. Đưa ra gợi ý khắc phục cụ thể\n"
        "4. Giải thích tại sao một vấn đề là nguy hiểm\n"
        "5. Đặc biệt chú ý đến secrets và mobile security\n\n"
        "Luôn đảm bảo đưa ra lời khuyên bảo mật thực tế và có thể áp dụng được."
    ),
    tools=[
        scan_code_directory,
        scan_code_files, 
        quick_security_check,
        scan_with_custom_rule,
        get_supported_languages,
        analyze_code_structure,
        analyze_project_architecture,
        get_semgrep_rule_schema,
        intelligent_project_analysis,
        scan_for_secrets,
        scan_android_project,
        scan_flutter_project
    ],
) 