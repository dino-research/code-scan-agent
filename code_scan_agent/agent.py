"""
Code Scan Agent - Main agent module
Sử dụng Google ADK và Semgrep MCP để scan code tìm lỗ hổng bảo mật
"""
import atexit
import concurrent.futures
import json
import logging
import os
import threading
from pathlib import Path
from typing import Dict, List, Any, Optional

from google.adk.agents import Agent
from .semgrep_client import SemgrepMCPClient

# Cấu hình logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Thread-safe client management
_client_lock = threading.Lock()
semgrep_client = None


def get_semgrep_client() -> SemgrepMCPClient:
    """Lấy hoặc tạo Semgrep client instance (thread-safe)"""
    global semgrep_client
    
    with _client_lock:
        if semgrep_client is None:
            semgrep_client = SemgrepMCPClient()
        return semgrep_client


def cleanup_semgrep_client():
    """Cleanup Semgrep client"""
    global semgrep_client
    
    with _client_lock:
        if semgrep_client is not None:
            try:
                # Cleanup sẽ được xử lý trong destructor của SemgrepMCPClient
                semgrep_client = None
            except Exception as e:
                logger.warning(f"Error during cleanup: {e}")


atexit.register(cleanup_semgrep_client)


def scan_code_directory(directory_path: str, config: Optional[str] = None) -> Dict[str, Any]:
    """
    Scan toàn bộ thư mục code để tìm lỗ hổng bảo mật
    
    Args:
        directory_path (str): Đường dẫn đến thư mục cần scan
        config (str, optional): Cấu hình Semgrep (ví dụ: 'auto', 'p/security-audit')
        
    Returns:
        dict: Kết quả scan bao gồm các lỗ hổng tìm thấy
    """
    try:
        # Kiểm tra đường dẫn có tồn tại không
        if not Path(directory_path).exists():
            return {
                "status": "error",
                "error_message": f"Thư mục '{directory_path}' không tồn tại."
            }
        
        # Chạy scan
        client = get_semgrep_client()
        result = client.scan_directory(directory_path, config)
        
        # Format kết quả để dễ đọc
        if "content" in result:
            scan_results = result["content"]
            if isinstance(scan_results, list) and len(scan_results) > 0:
                findings_count = len(scan_results)
                summary = f"Tìm thấy {findings_count} vấn đề bảo mật trong thư mục '{directory_path}'"
                
                # Phân loại theo mức độ nghiêm trọng
                severity_counts = {}
                for finding in scan_results:
                    severity = finding.get("extra", {}).get("severity", "unknown")
                    severity_counts[severity] = severity_counts.get(severity, 0) + 1
                
                return {
                    "status": "success",
                    "summary": summary,
                    "total_findings": findings_count,
                    "severity_breakdown": severity_counts,
                    "detailed_results": scan_results[:10],  # Giới hạn 10 kết quả đầu
                    "note": f"Hiển thị 10/{findings_count} kết quả đầu tiên" if findings_count > 10 else None
                }
            else:
                return {
                    "status": "success",
                    "summary": f"Không tìm thấy vấn đề bảo mật nào trong thư mục '{directory_path}'",
                    "total_findings": 0,
                    "detailed_results": []
                }
        
        return {
            "status": "success",
            "result": result
        }
        
    except Exception as e:
        logger.error(f"Lỗi khi scan thư mục {directory_path}: {e}")
        return {
            "status": "error",
            "error_message": f"Lỗi khi scan: {str(e)}"
        }


def scan_code_files(file_paths: List[str], config: Optional[str] = None) -> Dict[str, Any]:
    """
    Scan các file code cụ thể để tìm lỗ hổng bảo mật
    
    Args:
        file_paths (List[str]): Danh sách đường dẫn file cần scan
        config (str, optional): Cấu hình Semgrep
        
    Returns:
        dict: Kết quả scan
    """
    try:
        code_files = []
        
        for file_path in file_paths:
            path = Path(file_path)
            if not path.exists():
                return {
                    "status": "error", 
                    "error_message": f"File '{file_path}' không tồn tại."
                }
            
            try:
                content = path.read_text(encoding='utf-8', errors='ignore')
                code_files.append({
                    "filename": str(path.name),
                    "content": content
                })
            except Exception as e:
                logger.warning(f"Không thể đọc file {file_path}: {e}")
        
        if not code_files:
            return {
                "status": "error",
                "error_message": "Không có file nào được đọc thành công."
            }
        
        # Chạy scan
        client = get_semgrep_client()
        result = client.scan_code_files(code_files, config)
        
        return {
            "status": "success",
            "files_scanned": len(code_files),
            "result": result
        }
        
    except Exception as e:
        logger.error(f"Lỗi khi scan files: {e}")
        return {
            "status": "error",
            "error_message": f"Lỗi khi scan: {str(e)}"
        }


def quick_security_check(code_content: str, language: str) -> Dict[str, Any]:
    """
    Thực hiện kiểm tra bảo mật nhanh cho một đoạn code
    
    Args:
        code_content (str): Nội dung code cần kiểm tra
        language (str): Ngôn ngữ lập trình (ví dụ: python, javascript, java)
        
    Returns:
        dict: Kết quả kiểm tra bảo mật
    """
    try:
        # Tạo file giả với extension phù hợp
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
        
        extension = file_extensions.get(language.lower(), '.txt')
        filename = f"temp_code{extension}"
        
        code_files = [{
            "filename": filename,
            "content": code_content
        }]
        
        client = get_semgrep_client()
        result = client.security_check(code_files)
        
        return {
            "status": "success",
            "language": language,
            "result": result
        }
        
    except Exception as e:
        logger.error(f"Lỗi khi kiểm tra bảo mật: {e}")
        return {
            "status": "error",
            "error_message": f"Lỗi khi kiểm tra: {str(e)}"
        }


def scan_with_custom_rule(code_content: str, rule: str, language: str = "python") -> Dict[str, Any]:
    """
    Scan code với custom Semgrep rule
    
    Args:
        code_content (str): Nội dung code cần scan
        rule (str): Custom Semgrep rule (YAML format)
        language (str): Ngôn ngữ lập trình
        
    Returns:
        dict: Kết quả scan với custom rule
    """
    try:
        # Map language to file extension
        file_extensions = {
            'python': '.py',
            'javascript': '.js',
            'typescript': '.ts', 
            'java': '.java',
            'c': '.c',
            'cpp': '.cpp'
        }
        
        extension = file_extensions.get(language.lower(), '.py')
        filename = f"custom_scan{extension}"
        
        code_files = [{
            "filename": filename,
            "content": code_content
        }]
        
        client = get_semgrep_client()
        result = client.scan_with_custom_rule(code_files, rule)
        
        return {
            "status": "success",
            "language": language,
            "custom_rule_used": True,
            "result": result
        }
        
    except Exception as e:
        logger.error(f"Lỗi khi scan với custom rule: {e}")
        return {
            "status": "error",
            "error_message": f"Lỗi khi scan: {str(e)}"
        }


def get_supported_languages() -> Dict[str, Any]:
    """
    Lấy danh sách ngôn ngữ được Semgrep hỗ trợ
    
    Returns:
        dict: Danh sách ngôn ngữ được hỗ trợ
    """
    try:
        client = get_semgrep_client()
        languages = client.get_supported_languages()
        
        return {
            "status": "success",
            "supported_languages": languages,
            "total_languages": len(languages) if languages else 0
        }
        
    except Exception as e:
        logger.error(f"Lỗi khi lấy danh sách ngôn ngữ: {e}")
        return {
            "status": "error",
            "error_message": f"Lỗi khi lấy danh sách: {str(e)}"
        }


def analyze_code_structure(code_content: str, language: str) -> Dict[str, Any]:
    """
    Phân tích cấu trúc code bằng AST
    
    Args:
        code_content (str): Nội dung code
        language (str): Ngôn ngữ lập trình
        
    Returns:
        dict: Thông tin về cấu trúc code
    """
    try:
        client = get_semgrep_client()
        ast_result = client.get_abstract_syntax_tree(code_content, language)
        
        return {
            "status": "success",
            "language": language,
            "ast_analysis": ast_result
        }
        
    except Exception as e:
        logger.error(f"Lỗi khi phân tích cấu trúc code: {e}")
        return {
            "status": "error",
            "error_message": f"Lỗi khi phân tích: {str(e)}"
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
        analyze_code_structure
    ],
) 