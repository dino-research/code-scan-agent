"""
Unified Intelligent Agents Module
--------------------------------
Kết hợp chức năng của `intelligent_workflows.py` và `intelligent_scanner.py` vào một
facade duy nhất để đơn giản hóa import trong toàn bộ project.

• Re-exports tất cả class/đối tượng từ intelligent_workflows
• Re-exports các agents & scanner từ intelligent_scanner
• Đảm bảo cả hai module sử dụng cùng một lớp `Agent` cơ sở (custom)
"""

from __future__ import annotations

import importlib
import sys
from types import ModuleType
from typing import Any

# Import intelligent_workflows trước để có custom Agent
int_workflows: ModuleType = importlib.import_module("code_scan_agent.intelligent_workflows")

# Ensure module is available as sub-attr của facade
globals().update({k: v for k, v in vars(int_workflows).items() if not k.startswith("__")})

# Import intelligent_scanner (will fallback to custom Agent)
int_scanner: ModuleType = importlib.import_module("code_scan_agent.intelligent_scanner")

# Monkey-patch intelligent_scanner.Agent để trỏ tới custom Agent nếu cần
if getattr(int_scanner, "Agent", None) is not int_workflows.Agent:
    int_scanner.Agent = int_workflows.Agent  # type: ignore

# Re-export các thành phần quan trọng từ intelligent_scanner
export_names = [
    "RuleAnalysisAgent",
    "CodePatternAgent",
    "OptimizedSecurityScanAgent",
    "IntelligentCodeScanner",
    "intelligent_scan_code_directory",
]
for name in export_names:
    globals()[name] = getattr(int_scanner, name)

# Convenience alias cho orchestrator
intelligent_workflow_orchestrator = int_workflows.intelligent_workflow_orchestrator  # noqa: E501

__all__ = list({*globals().keys()})  # export everything 