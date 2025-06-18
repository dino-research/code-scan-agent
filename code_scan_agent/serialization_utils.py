"""
Serialization Utilities - Robust JSON handling cho Code Scan Agent

Cung cấp safe serialization/deserialization với comprehensive error handling,
type validation, và encoding safety.
"""
import json
import logging
from typing import Any, Dict, List, Optional, Union, Type
from pathlib import Path
import traceback

from .errors import ErrorCode, ErrorSeverity, CodeScanException

logger = logging.getLogger(__name__)


class SerializationError(CodeScanException):
    """Specialized exception for serialization errors"""
    def __init__(self, message: str, data_type: str = "unknown", **kwargs):
        super().__init__(
            code=ErrorCode.SCAN_RESULT_PARSE_ERROR,
            message=message,
            severity=ErrorSeverity.MEDIUM,
            component="serialization_utils",
            additional_data={"data_type": data_type},
            **kwargs
        )


def safe_json_loads(
    json_string: str, 
    default: Any = None,
    raise_on_error: bool = False,
    context: str = "unknown"
) -> Any:
    """
    Safely parse JSON string với comprehensive error handling
    
    Args:
        json_string: JSON string để parse
        default: Default value nếu parsing fails
        raise_on_error: Có raise exception không nếu parse fail
        context: Context thông tin cho logging
        
    Returns:
        Parsed object hoặc default value
        
    Raises:
        SerializationError: Nếu raise_on_error=True và parsing fails
    """
    if not isinstance(json_string, str):
        error_msg = f"Expected string for JSON parsing, got {type(json_string)}"
        logger.warning(f"[{context}] {error_msg}")
        if raise_on_error:
            raise SerializationError(
                message=error_msg,
                data_type=str(type(json_string)),
                operation="safe_json_loads"
            )
        return default
    
    if not json_string.strip():
        logger.debug(f"[{context}] Empty JSON string provided")
        return default
    
    try:
        result = json.loads(json_string)
        logger.debug(f"[{context}] Successfully parsed JSON ({len(json_string)} chars)")
        return result
        
    except json.JSONDecodeError as e:
        error_msg = f"JSON decode error: {e.msg} at line {e.lineno}, column {e.colno}"
        logger.error(f"[{context}] {error_msg}")
        
        if raise_on_error:
            raise SerializationError(
                message=error_msg,
                data_type="json_string",
                operation="safe_json_loads",
                original_exception=e
            )
        return default
        
    except Exception as e:
        error_msg = f"Unexpected error during JSON parsing: {e}"
        logger.error(f"[{context}] {error_msg}")
        
        if raise_on_error:
            raise SerializationError(
                message=error_msg,
                data_type="json_string",
                operation="safe_json_loads",
                original_exception=e
            )
        return default


def safe_json_dumps(
    obj: Any,
    default_str: str = "{}",
    raise_on_error: bool = False,
    context: str = "unknown",
    **json_kwargs
) -> str:
    """
    Safely serialize object to JSON string
    
    Args:
        obj: Object để serialize
        default_str: Default JSON string nếu serialization fails
        raise_on_error: Có raise exception không nếu serialization fails
        context: Context thông tin cho logging
        **json_kwargs: Additional arguments cho json.dumps
        
    Returns:
        JSON string hoặc default_str
        
    Raises:
        SerializationError: Nếu raise_on_error=True và serialization fails
    """
    try:
        json_options = {
            'ensure_ascii': False,
            'indent': 2,
            'separators': (',', ': '),
            **json_kwargs
        }
        
        result = json.dumps(obj, **json_options)
        logger.debug(f"[{context}] Successfully serialized object to JSON ({len(result)} chars)")
        return result
        
    except TypeError as e:
        error_msg = f"Object not JSON serializable: {e}"
        logger.error(f"[{context}] {error_msg}")
        
        if raise_on_error:
            raise SerializationError(
                message=error_msg,
                data_type=str(type(obj)),
                operation="safe_json_dumps",
                original_exception=e
            )
        return default_str
        
    except Exception as e:
        error_msg = f"Unexpected error during JSON serialization: {e}"
        logger.error(f"[{context}] {error_msg}")
        
        if raise_on_error:
            raise SerializationError(
                message=error_msg,
                data_type=str(type(obj)),
                operation="safe_json_dumps",
                original_exception=e
            )
        return default_str


def parse_nested_json(
    data: Union[str, Dict, List],
    context: str = "nested_json"
) -> Dict[str, Any]:
    """
    Parse nested JSON structure với robust error handling
    Xử lý cases như JSON trong JSON, MCP response formats, etc.
    
    Args:
        data: Data để parse (có thể là string, dict, hoặc list)
        context: Context cho logging
        
    Returns:
        Dict chứa parsed data hoặc error information
    """
    result = {
        "status": "success",
        "data": None,
        "format_detected": "unknown",
        "parsing_notes": []
    }
    
    try:
        if isinstance(data, dict):
            result["data"] = data
            result["format_detected"] = "direct_dict"
            return result
        
        elif isinstance(data, list):
            if not data:
                result["data"] = {"items": []}
                result["format_detected"] = "empty_list"
                return result
            
            first_item = data[0]
            if isinstance(first_item, dict) and "text" in first_item:
                text_content = first_item.get("text", "")
                nested_data = safe_json_loads(text_content, default={}, context=f"{context}_mcp_text")
                result["data"] = nested_data
                result["format_detected"] = "mcp_text_format"
            else:
                result["data"] = {"items": data}
                result["format_detected"] = "direct_list"
            
            return result
        
        elif isinstance(data, str):
            if not data.strip():
                result["data"] = {}
                result["format_detected"] = "empty_string"
                return result
            
            parsed = safe_json_loads(data, default=None, context=f"{context}_string")
            if parsed is not None:
                result["data"] = parsed
                result["format_detected"] = "json_string"
            else:
                result["data"] = {"raw_content": data}
                result["format_detected"] = "raw_string"
            
            return result
        
        else:
            result["data"] = {"value": data, "type": str(type(data))}
            result["format_detected"] = f"other_{type(data).__name__}"
            return result
    
    except Exception as e:
        logger.error(f"[{context}] Error in parse_nested_json: {e}")
        result["status"] = "error"
        result["error"] = str(e)
        result["data"] = {"raw_input": str(data) if data is not None else None}
        return result


def validate_json_structure(
    data: Dict[str, Any],
    required_fields: List[str] = None,
    expected_types: Dict[str, Type] = None,
    context: str = "validation"
) -> Dict[str, Any]:
    """
    Validate JSON structure và types
    
    Args:
        data: Data để validate
        required_fields: List các field bắt buộc
        expected_types: Dict mapping field names to expected types
        context: Context cho logging
        
    Returns:
        Dict chứa validation results
    """
    validation_result = {
        "is_valid": True,
        "errors": [],
        "warnings": [],
        "field_summary": {}
    }
    
    if not isinstance(data, dict):
        validation_result["is_valid"] = False
        validation_result["errors"].append(f"Expected dict, got {type(data)}")
        return validation_result
    
    # Check required fields
    if required_fields:
        for field in required_fields:
            if field not in data:
                validation_result["is_valid"] = False
                validation_result["errors"].append(f"Missing required field: {field}")
            else:
                validation_result["field_summary"][field] = "present"
    
    # Check types
    if expected_types:
        for field, expected_type in expected_types.items():
            if field in data:
                actual_value = data[field]
                if not isinstance(actual_value, expected_type):
                    validation_result["warnings"].append(
                        f"Field '{field}' expected {expected_type.__name__}, got {type(actual_value).__name__}"
                    )
                    validation_result["field_summary"][field] = f"type_mismatch_{type(actual_value).__name__}"
                else:
                    validation_result["field_summary"][field] = "valid_type"
    
    logger.debug(f"[{context}] Validation result: {validation_result['is_valid']}, "
                f"errors: {len(validation_result['errors'])}, warnings: {len(validation_result['warnings'])}")
    
    return validation_result


def safe_file_read_json(
    file_path: Union[str, Path],
    default: Any = None,
    encoding: str = "utf-8",
    context: str = "file_read"
) -> Any:
    """
    Safely read JSON from file với error handling
    
    Args:
        file_path: Path to JSON file
        default: Default value nếu read fails
        encoding: File encoding
        context: Context cho logging
        
    Returns:
        Parsed JSON data hoặc default value
    """
    try:
        path = Path(file_path)
        if not path.exists():
            logger.warning(f"[{context}] File does not exist: {file_path}")
            return default
        
        with open(path, 'r', encoding=encoding, errors='replace') as f:
            content = f.read()
        
        return safe_json_loads(content, default=default, context=f"{context}_file")
        
    except Exception as e:
        logger.error(f"[{context}] Error reading JSON file {file_path}: {e}")
        return default


def safe_file_write_json(
    data: Any,
    file_path: Union[str, Path],
    encoding: str = "utf-8",
    context: str = "file_write",
    **json_kwargs
) -> bool:
    """
    Safely write JSON to file
    
    Args:
        data: Data để write
        file_path: Path to target file
        encoding: File encoding
        context: Context cho logging
        **json_kwargs: Additional JSON options
        
    Returns:
        True nếu write thành công, False otherwise
    """
    try:
        path = Path(file_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        
        json_content = safe_json_dumps(
            data, 
            raise_on_error=True, 
            context=f"{context}_write",
            **json_kwargs
        )
        
        with open(path, 'w', encoding=encoding) as f:
            f.write(json_content)
        
        logger.debug(f"[{context}] Successfully wrote JSON to {file_path}")
        return True
        
    except Exception as e:
        logger.error(f"[{context}] Error writing JSON file {file_path}: {e}")
        return False


def extract_scan_results(
    raw_data: Any,
    context: str = "scan_results"
) -> Dict[str, Any]:
    """
    Extract scan results từ various formats (MCP, direct, nested JSON)
    Specialized function cho Semgrep scan results
    
    Args:
        raw_data: Raw data từ scan operation
        context: Context cho logging
        
    Returns:
        Dict chứa normalized scan results
    """
    extraction_result = {
        "status": "success",
        "findings": [],
        "metadata": {},
        "format_info": {},
        "errors": []
    }
    
    try:
        parsed = parse_nested_json(raw_data, context=f"{context}_extraction")
        
        if parsed["status"] != "success":
            extraction_result["status"] = "error"
            extraction_result["errors"].append(f"Failed to parse data: {parsed.get('error', 'unknown')}")
            return extraction_result
        
        data = parsed["data"]
        extraction_result["format_info"] = {
            "detected_format": parsed["format_detected"],
            "parsing_notes": parsed["parsing_notes"]
        }
        
        if isinstance(data, dict):
            if "results" in data:
                extraction_result["findings"] = data["results"]
                extraction_result["metadata"]["total_results"] = len(data["results"])
            elif "items" in data:
                extraction_result["findings"] = data["items"]
                extraction_result["metadata"]["total_results"] = len(data["items"])
            elif any(key in data for key in ["check_id", "path", "extra", "rule_id"]):
                extraction_result["findings"] = [data]
                extraction_result["metadata"]["total_results"] = 1
            else:
                extraction_result["metadata"]["raw_data"] = data
                extraction_result["metadata"]["total_results"] = 0
        
        elif isinstance(data, list):
            extraction_result["findings"] = data
            extraction_result["metadata"]["total_results"] = len(data)
        
        else:
            extraction_result["metadata"]["raw_data"] = data
            extraction_result["metadata"]["total_results"] = 0
        
        logger.info(f"[{context}] Extracted {extraction_result['metadata'].get('total_results', 0)} findings")
        
    except Exception as e:
        logger.error(f"[{context}] Error extracting scan results: {e}")
        extraction_result["status"] = "error"
        extraction_result["errors"].append(str(e))
    
    return extraction_result 