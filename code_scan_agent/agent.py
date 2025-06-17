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

from google.adk.agents import Agent
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


def format_scan_results(raw_result: Dict[str, Any], context: str = "") -> Dict[str, Any]:
    """Format scan results cho human-readable output"""
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
        
        # Extract content từ MCP response
        content = raw_result.get("content", [])
        
        if isinstance(content, list):
            findings_count = len(content)
            
            if findings_count == 0:
                return {
                    "status": "success",
                    "summary": f"✅ Không tìm thấy vấn đề bảo mật nào{' trong ' + context if context else ''}",
                    "total_findings": 0,
                    "detailed_results": []
                }
            
            # Phân loại theo mức độ nghiêm trọng
            severity_counts = {}
            high_severity_findings = []
            
            for finding in content:
                if isinstance(finding, dict):
                    severity = finding.get("extra", {}).get("severity", "info").lower()
                    severity_counts[severity] = severity_counts.get(severity, 0) + 1
                    
                    # Collect high severity findings
                    if severity in ["error", "warning"]:
                        high_severity_findings.append({
                            "rule_id": finding.get("check_id", "unknown"),
                            "message": finding.get("extra", {}).get("message", "No message"),
                            "severity": severity,
                            "file": finding.get("path", "unknown"),
                            "line": finding.get("start", {}).get("line", "unknown")
                        })
            
            summary = f"🔍 Tìm thấy {findings_count} vấn đề{' trong ' + context if context else ''}"
            
            return {
                "status": "success",
                "summary": summary,
                "total_findings": findings_count,
                "severity_breakdown": severity_counts,
                "high_severity_findings": high_severity_findings[:5],  # Top 5 critical issues
                "detailed_results": content[:10],  # First 10 detailed results
                "note": f"Hiển thị top issues từ {findings_count} kết quả" if findings_count > 10 else None
            }
        
        # Fallback for other response formats
        return {
            "status": "success",
            "raw_result": raw_result
        }
        
    except Exception as e:
        logger.error(f"Error formatting scan results: {e}")
        return {
            "status": "error",
            "error_message": f"Failed to format results: {str(e)}",
            "raw_result": raw_result
        }


@handle_errors("agent", "scan_code_directory")  
def scan_code_directory(directory_path: str, config: Optional[str] = None) -> Dict[str, Any]:
    """
    Scan toàn bộ thư mục code để tìm lỗ hổng bảo mật với enhanced error handling
    
    Args:
        directory_path (str): Đường dẫn đến thư mục cần scan
        config (str, optional): Cấu hình Semgrep (ví dụ: 'auto', 'p/security-audit')
        
    Returns:
        dict: Kết quả scan bao gồm các lỗ hổng tìm thấy
    """
    try:
        # Validate input
        validated_path = validate_directory_path(directory_path)
        
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
                "scan_type": "directory",
                "scan_target": str(validated_path),
                "config_used": config or "default"
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


def scan_code_files(file_paths: List[str], config: Optional[str] = None) -> Dict[str, Any]:
    """
    Scan các file code cụ thể để tìm lỗ hổng bảo mật với improved validation
    
    Args:
        file_paths (List[str]): Danh sách đường dẫn file cần scan
        config (str, optional): Cấu hình Semgrep
        
    Returns:
        dict: Kết quả scan
    """
    try:
        # Validate input
        validated_paths = validate_file_paths(file_paths)
        
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


def quick_security_check(code_content: str, language: str) -> Dict[str, Any]:
    """
    Thực hiện kiểm tra bảo mật nhanh cho một đoạn code với validation
    
    Args:
        code_content (str): Nội dung code cần kiểm tra
        language (str): Ngôn ngữ lập trình (ví dụ: python, javascript, java)
        
    Returns:
        dict: Kết quả kiểm tra bảo mật
    """
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


def scan_with_custom_rule(code_content: str, rule: str, language: str = "python") -> Dict[str, Any]:
    """
    Scan code với custom Semgrep rule
    
    Args:
        code_content (str): Nội dung code cần scan
        rule (str): Custom Semgrep rule (YAML format)
        language (str): Ngôn ngữ lập trình
        
    Returns:
        dict: Kết quả scan
    """
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


def get_supported_languages() -> Dict[str, Any]:
    """
    Lấy danh sách ngôn ngữ lập trình được hỗ trợ bởi Semgrep
    
    Returns:
        dict: Danh sách ngôn ngữ và thông tin liên quan
    """
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


def analyze_code_structure(code_content: str, language: str) -> Dict[str, Any]:
    """
    Phân tích cấu trúc code bằng Abstract Syntax Tree (AST)
    
    Args:
        code_content (str): Nội dung code cần phân tích
        language (str): Ngôn ngữ lập trình
        
    Returns:
        dict: Cấu trúc AST và thông tin phân tích
    """
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


def get_semgrep_rule_schema() -> Dict[str, Any]:
    """
    Lấy schema định nghĩa cho Semgrep rules
    
    Returns:
        dict: Schema và documentation cho việc tạo custom rules
    """
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


# Định nghĩa root agent với ADK
root_agent = Agent(
    name="code_scan_agent",
    model="gemini-2.0-flash",
    description=(
        "Agent chuyên về scan code để tìm lỗ hổng bảo mật sử dụng Semgrep. "
        "Có thể scan thư mục, file cụ thể, hoặc đoạn code với các rule tùy chỉnh."
    ),
    instruction=(
        "Bạn là một chuyên gia bảo mật code có thể giúp scan và phân tích code để tìm các lỗ hổng bảo mật. "
        "Bạn sử dụng Semgrep - một công cụ static analysis mạnh mẽ để phát hiện:\n"
        "- Lỗ hổng bảo mật (SQL injection, XSS, etc.)\n"
        "- Code smells và bad practices\n"
        "- Compliance violations\n"
        "- Custom security rules\n\n"
        "Khi trả lời, hãy:\n"
        "1. Tóm tắt kết quả scan một cách rõ ràng\n"
        "2. Ưu tiên các vấn đề theo mức độ nghiêm trọng\n"
        "3. Đưa ra gợi ý khắc phục cụ thể\n"
        "4. Giải thích tại sao một vấn đề là nguy hiểm\n\n"
        "Luôn đảm bảo đưa ra lời khuyên bảo mật thực tế và có thể áp dụng được."
    ),
    tools=[
        scan_code_directory,
        scan_code_files, 
        quick_security_check,
        scan_with_custom_rule,
        get_supported_languages,
        analyze_code_structure,
        get_semgrep_rule_schema
    ],
) 