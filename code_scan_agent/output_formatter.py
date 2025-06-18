"""
Enhanced Output Formatter cho Code Scan Agent

Cung cấp rich formatting cho scan results với:
- Code snippets với context lines
- Syntax highlighting (nếu có thể)
- Line numbers rõ ràng
- Visual indicators cho vulnerabilities
- Detailed file information
"""
import logging
import re
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Union
import textwrap

from .errors import ErrorCode, ErrorSeverity, CodeScanException, handle_errors

logger = logging.getLogger(__name__)


class OutputFormatter:
    """Enhanced formatter cho scan results với code snippets"""
    
    def __init__(self, context_lines: int = 3, max_line_length: int = 120, show_line_numbers: bool = True):
        self.context_lines = context_lines
        self.max_line_length = max_line_length
        self.show_line_numbers = show_line_numbers
    
    def format_enhanced_results(self, scan_results: Dict[str, Any], scan_target: Optional[str] = None) -> Dict[str, Any]:
        """Format scan results với enhanced output"""
        try:
            if scan_results.get("status") != "success":
                return scan_results
            
            findings = scan_results.get("detailed_results", [])
            if not findings:
                return self._format_no_findings_message(scan_results, scan_target)
            
            enhanced_findings = []
            for finding in findings:
                enhanced_finding = self._enhance_single_finding(finding, scan_target)
                if enhanced_finding:
                    enhanced_findings.append(enhanced_finding)
            
            enhanced_summary = self._create_enhanced_summary(scan_results, enhanced_findings)
            
            return {
                **scan_results,
                "enhanced_output": True,
                "enhanced_summary": enhanced_summary,
                "enhanced_findings": enhanced_findings[:10]
            }
            
        except Exception as e:
            logger.error(f"Error in enhanced formatting: {e}")
            return scan_results
    
    def _enhance_single_finding(self, finding: Dict[str, Any], scan_target: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Enhance một finding với code snippet"""
        try:
            if not isinstance(finding, dict):
                return None
            
            file_path = finding.get("path", "")
            start_line = finding.get("start", {}).get("line", 0)
            end_line = finding.get("end", {}).get("line", start_line)
            rule_id = finding.get("check_id", "unknown")
            message = finding.get("extra", {}).get("message", "No message")
            severity = finding.get("extra", {}).get("severity", "info")
            
            enhanced = {
                "rule_id": rule_id,
                "severity": severity.lower(),
                "message": message,
                "file_info": {
                    "path": file_path,
                    "relative_path": self._get_relative_path(file_path, scan_target),
                    "start_line": start_line,
                    "end_line": end_line,
                    "line_range": f"{start_line}-{end_line}" if end_line != start_line else str(start_line)
                },
                "severity_icon": self._get_severity_icon(severity),
                "code_snippet": None,
                "original_finding": finding
            }
            
            code_snippet = self._extract_code_snippet(file_path, start_line, end_line, scan_target)
            if code_snippet:
                enhanced["code_snippet"] = code_snippet
            
            return enhanced
            
        except Exception as e:
            logger.warning(f"Error enhancing finding: {e}")
            return None
    
    def _extract_code_snippet(self, file_path: str, start_line: int, end_line: int, scan_target: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Extract code snippet với context lines"""
        try:
            if scan_target and not Path(file_path).is_absolute():
                full_path = Path(scan_target) / file_path
            else:
                full_path = Path(file_path)
            
            if not full_path.exists() or not full_path.is_file():
                return None
            
            with open(full_path, 'r', encoding='utf-8', errors='replace') as f:
                lines = f.readlines()
            
            if not lines:
                return None
            
            total_lines = len(lines)
            start_idx = max(0, start_line - 1)
            end_idx = min(total_lines, end_line)
            
            context_start = max(0, start_idx - self.context_lines)
            context_end = min(total_lines, end_idx + self.context_lines)
            
            snippet_lines = []
            for i in range(context_start, context_end):
                line_num = i + 1
                line_content = lines[i].rstrip('\n\r')
                
                if len(line_content) > self.max_line_length:
                    line_content = line_content[:self.max_line_length - 3] + "..."
                
                is_vulnerable = start_line <= line_num <= end_line
                
                snippet_lines.append({
                    "line_number": line_num,
                    "content": line_content,
                    "is_vulnerable": is_vulnerable,
                    "formatted": self._format_code_line(line_num, line_content, is_vulnerable)
                })
            
            return {
                "total_lines": total_lines,
                "context_start": context_start + 1,
                "context_end": context_end,
                "vulnerable_start": start_line,
                "vulnerable_end": end_line,
                "lines": snippet_lines
            }
            
        except Exception as e:
            logger.warning(f"Error extracting code snippet from {file_path}: {e}")
            return None
    
    def _format_code_line(self, line_num: int, content: str, is_vulnerable: bool) -> str:
        """Format một line của code"""
        if self.show_line_numbers:
            line_num_str = f"{line_num:4d}"
        else:
            line_num_str = ""
        
        indicator = "►" if is_vulnerable else "│"
        
        if self.show_line_numbers:
            return f"{line_num_str} {indicator} {content}"
        else:
            return f"{indicator} {content}"
    
    def _get_relative_path(self, file_path: str, scan_target: Optional[str] = None) -> str:
        """Get relative path cho display"""
        try:
            if not scan_target:
                return file_path
            
            target_path = Path(scan_target)
            file_abs_path = Path(file_path)
            
            if file_abs_path.is_absolute():
                try:
                    return str(file_abs_path.relative_to(target_path))
                except ValueError:
                    return file_path
            else:
                return file_path
                
        except Exception:
            return file_path
    
    def _get_severity_icon(self, severity: str) -> str:
        """Get icon cho severity"""
        severity_lower = severity.lower()
        severity_map = {
            "error": "🔴",
            "warning": "🟡",
            "info": "🔵"
        }
        return severity_map.get(severity_lower, "🔵")
    
    def _create_enhanced_summary(self, scan_results: Dict[str, Any], enhanced_findings: List[Dict[str, Any]]) -> str:
        """Create enhanced text summary"""
        total_findings = scan_results.get("total_findings", 0)
        severity_breakdown = scan_results.get("severity_breakdown", {})
        
        lines = []
        lines.append("🔍 Security Scan Results")
        lines.append("=" * 50)
        
        if total_findings == 0:
            lines.append("✅ No security issues found")
            return "\n".join(lines)
        
        lines.append(f"Total Issues Found: {total_findings}")
        
        if severity_breakdown:
            lines.append("\nSeverity Breakdown:")
            for severity, count in sorted(severity_breakdown.items(), key=lambda x: {"error": 3, "warning": 2, "info": 1}.get(x[0], 0), reverse=True):
                icon = self._get_severity_icon(severity)
                lines.append(f"  {icon} {severity.upper()}: {count}")
        
        if enhanced_findings:
            lines.append("\nTop Issues:")
            for i, finding in enumerate(enhanced_findings[:3], 1):
                file_info = finding["file_info"]
                lines.append(f"  {i}. {finding['severity_icon']} {finding['rule_id']} in {file_info['relative_path']}:{file_info['line_range']}")
        
        return "\n".join(lines)
    
    def _format_no_findings_message(self, scan_results: Dict[str, Any], scan_target: Optional[str] = None) -> Dict[str, Any]:
        """Format message khi không có findings"""
        target_info = f" in {scan_target}" if scan_target else ""
        
        enhanced_summary = f"""🔍 Security Scan Results
{'=' * 50}
✅ No security issues found{target_info}

Your code appears to be secure based on the configured rules."""
        
        return {
            **scan_results,
            "enhanced_output": True,
            "enhanced_summary": enhanced_summary,
            "enhanced_findings": []
        }
    
    def generate_report_text(self, enhanced_results: Dict[str, Any]) -> str:
        """Generate full text report"""
        lines = []
        
        if "enhanced_summary" in enhanced_results:
            lines.append(enhanced_results["enhanced_summary"])
            lines.append("")
        
        enhanced_findings = enhanced_results.get("enhanced_findings", [])
        if enhanced_findings:
            lines.append("Detailed Findings:")
            lines.append("")
            
            for i, finding in enumerate(enhanced_findings, 1):
                lines.extend(self._format_detailed_finding(finding, i))
                lines.append("")
        
        return "\n".join(lines)
    
    def _format_detailed_finding(self, finding: Dict[str, Any], index: int) -> List[str]:
        """Format detailed finding với code snippet"""
        lines = []
        
        file_info = finding["file_info"]
        
        lines.append(f"{index}. {finding['severity_icon']} {finding['rule_id']}")
        lines.append(f"   {finding['severity'].upper()}: {finding['message']}")
        lines.append(f"   📁 File: {file_info['relative_path']} (line {file_info['line_range']})")
        
        code_snippet = finding.get("code_snippet")
        if code_snippet:
            lines.append("")
            lines.append("   Code Context:")
            
            for line_info in code_snippet["lines"]:
                lines.append(f"   {line_info['formatted']}")
        
        return lines


def format_enhanced_scan_results(scan_results: Dict[str, Any], scan_target: Optional[str] = None, **options) -> Dict[str, Any]:
    """Convenience function để format scan results"""
    formatter = OutputFormatter(**options)
    return formatter.format_enhanced_results(scan_results, scan_target)


def generate_enhanced_report(scan_results: Dict[str, Any], scan_target: Optional[str] = None, **options) -> str:
    """Generate full enhanced report"""
    formatter = OutputFormatter(**options)
    enhanced_results = formatter.format_enhanced_results(scan_results, scan_target)
    return formatter.generate_report_text(enhanced_results) 