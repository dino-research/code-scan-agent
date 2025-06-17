"""
Code Scan Agent

AI-driven code security scanning tool powered by Google ADK and Semgrep MCP.
Provides comprehensive code analysis, vulnerability detection, and intelligent 
scanning capabilities.

Core modules:
- agent: Main scanning functions
- intelligent: AI-powered intelligent scanning features
- semgrep_client: Interface to Semgrep MCP Server
- errors: Error handling system
"""

from .agent import (
    scan_code_directory,
    scan_code_files,
    quick_security_check,
    scan_with_custom_rule,
    get_supported_languages,
    analyze_code_structure,
    get_semgrep_rule_schema,
    intelligent_project_analysis,
    analyze_project_architecture,
)

__all__ = [
    # Main scanning functions
    "scan_code_directory",
    "scan_code_files",
    "quick_security_check",
    "scan_with_custom_rule",
    
    # Analysis tools
    "get_supported_languages",
    "analyze_code_structure",
    "get_semgrep_rule_schema",
    
    # Intelligent features
    "intelligent_project_analysis",
    "analyze_project_architecture",
]

# Version information
__version__ = "0.1.0"

__author__ = "Code Scan Agent Team" 