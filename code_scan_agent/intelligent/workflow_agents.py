"""
Workflow Agents

Module này chứa các agent cụ thể cho mỗi workflow.
Mỗi loại agent có nhiệm vụ riêng trong quy trình intelligence:
- Analysis Agents: Phân tích context và xác định yêu cầu
- Optimization Agents: Tối ưu hóa approach và parameters
- Execution Agents: Thực thi thông minh và nâng cao kết quả
"""

import logging
import re
from pathlib import Path
from typing import Dict, List, Any, Optional

from .agents import AnalysisAgent, OptimizationAgent, ExecutionAgent

logger = logging.getLogger(__name__)


# ============================================================================
# FILE SCAN WORKFLOW AGENTS
# ============================================================================

class FileScanAnalysisAgent(AnalysisAgent):
    """Agent phân tích files cần scan"""
    
    def __init__(self):
        super().__init__(name="FileScanAnalysisAgent")
    
    def _determine_requirements(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        """Xác định yêu cầu dựa trên file input"""
        args = inputs.get("args", [])
        if not args or len(args) < 1:
            return {"approach": "standard", "risk_level": "unknown"}
        
        try:
            # Extract file paths from args
            file_paths = args[0] if isinstance(args[0], list) else [args[0]]
            file_analysis = self._analyze_files(file_paths)
            
            # Determine requirements based on file analysis
            return {
                "approach": self._determine_approach(file_analysis),
                "risk_level": self._determine_risk_level(file_analysis),
                "file_analysis": file_analysis,
                "optimization_hints": {
                    "prioritize": file_analysis.get("has_risky_patterns", False),
                    "use_targeted_rules": file_analysis.get("has_framework_specific", False),
                    "execution_priority": "high" if file_analysis.get("high_risk_count", 0) > 0 else "normal"
                }
            }
            
        except Exception as e:
            logger.error(f"File analysis failed: {e}")
            return {"approach": "standard", "risk_level": "unknown", "error": str(e)}
    
    def _analyze_files(self, file_paths: List[str]) -> Dict[str, Any]:
        """Phân tích files để xác định yêu cầu scan"""
        languages = set()
        extensions = set()
        high_risk_patterns = 0
        framework_specific = False
        
        for path in file_paths[:10]:  # Limit to first 10 files for performance
            try:
                file_path = Path(path)
                if not file_path.exists() or not file_path.is_file():
                    continue
                
                # Extract extension and guess language
                extension = file_path.suffix.lower()
                extensions.add(extension)
                
                if extension in ['.py', '.pyx']:
                    languages.add('python')
                elif extension in ['.js', '.jsx']:
                    languages.add('javascript')
                elif extension in ['.ts', '.tsx']:
                    languages.add('typescript')
                elif extension in ['.java']:
                    languages.add('java')
                elif extension in ['.rb']:
                    languages.add('ruby')
                elif extension in ['.php']:
                    languages.add('php')
                elif extension in ['.go']:
                    languages.add('go')
                
                # Quick check for risky patterns
                try:
                    content = file_path.read_text(encoding='utf-8', errors='ignore')
                    high_risk_patterns += self._count_risky_patterns(content)
                    
                    # Check for framework specific code
                    if not framework_specific:
                        framework_specific = any(pattern in content.lower() for pattern in 
                                                ['django', 'flask', 'express', 'react', 'angular', 'spring'])
                except Exception:
                    pass
                
            except Exception as e:
                logger.debug(f"Error analyzing file {path}: {e}")
        
        return {
            "languages": list(languages),
            "extensions": list(extensions),
            "has_risky_patterns": high_risk_patterns > 0,
            "high_risk_count": high_risk_patterns,
            "has_framework_specific": framework_specific,
            "total_files": len(file_paths)
        }
    
    def _count_risky_patterns(self, content: str) -> int:
        """Count risky patterns in code content"""
        risky_patterns = [
            r"exec\s*\(", r"eval\s*\(", r"os\.system\s*\(", r"subprocess\.call\s*\(", 
            r"password\s*=", r"SELECT.*FROM.*WHERE", r"<\s*script", r"\.innerHTML\s*="
        ]
        
        count = 0
        for pattern in risky_patterns:
            count += len(re.findall(pattern, content))
        return count
    
    def _determine_approach(self, analysis: Dict[str, Any]) -> str:
        """Xác định approach dựa trên phân tích"""
        if analysis.get("high_risk_count", 0) > 3:
            return "comprehensive"
        elif analysis.get("has_framework_specific", False):
            return "targeted"
        else:
            return "standard"
    
    def _determine_risk_level(self, analysis: Dict[str, Any]) -> str:
        """Xác định risk level dựa trên phân tích"""
        if analysis.get("high_risk_count", 0) > 5:
            return "high"
        elif analysis.get("high_risk_count", 0) > 0:
            return "medium"
        else:
            return "low"


class FileScanOptimizationAgent(OptimizationAgent):
    """Agent tối ưu hóa file scanning"""
    
    def __init__(self):
        super().__init__(name="FileScanOptimizationAgent")
    
    def _create_optimization_strategy(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Tạo optimization strategy dựa trên phân tích"""
        requirements = analysis.get("requirements", {})
        approach = requirements.get("approach", "standard")
        risk_level = requirements.get("risk_level", "low")
        file_analysis = requirements.get("file_analysis", {})
        
        # Calculate rule priorities
        rule_priorities = self._calculate_rule_priorities(file_analysis)
        
        # Define execution mode
        execution_mode = "normal"
        if risk_level == "high":
            execution_mode = "detailed"
        elif approach == "comprehensive":
            execution_mode = "thorough"
        
        return {
            "strategy": approach,
            "rule_priorities": rule_priorities,
            "execution_mode": execution_mode,
            "risk_level": risk_level,
            "targeted_frameworks": self._get_targeted_frameworks(file_analysis)
        }
    
    def _optimize_parameters(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Tối ưu hóa parameters dựa trên phân tích"""
        requirements = analysis.get("requirements", {})
        hints = requirements.get("optimization_hints", {})
        file_analysis = requirements.get("file_analysis", {})
        
        # Enhanced parameters
        enhanced_params = {}
        
        # Use custom config if needed
        if hints.get("use_targeted_rules", False):
            languages = file_analysis.get("languages", [])
            if languages:
                # Build optimized config string
                rules = ["p/security-audit"]  # Always include security audit
                
                # Add language-specific rules
                primary_lang = languages[0] if languages else None
                if primary_lang:
                    rules.append(f"p/{primary_lang}")
                
                # Add framework rules
                frameworks = self._get_targeted_frameworks(file_analysis)
                for framework in frameworks:
                    rules.append(f"p/{framework}")
                
                enhanced_params["config"] = ",".join(rules)
        
        return enhanced_params
    
    def _calculate_rule_priorities(self, file_analysis: Dict[str, Any]) -> Dict[str, str]:
        """Calculate rule priorities based on file analysis"""
        rule_priorities = {}
        
        # Prioritize security rules for risky patterns
        if file_analysis.get("has_risky_patterns", False):
            rule_priorities["security"] = "high"
        else:
            rule_priorities["security"] = "medium"
            
        # Prioritize quality rules based on file count
        rule_priorities["quality"] = "medium" if file_analysis.get("total_files", 0) > 5 else "low"
            
        return rule_priorities
    
    def _get_targeted_frameworks(self, file_analysis: Dict[str, Any]) -> List[str]:
        """Get targeted frameworks based on file analysis"""
        languages = file_analysis.get("languages", [])
        frameworks = []
        
        # Simple mapping for demonstration purpose
        language_framework_map = {
            "python": ["django", "flask"],
            "javascript": ["react", "express", "vue"],
            "typescript": ["angular", "react"],
            "java": ["spring"],
            "ruby": ["rails"],
            "php": ["laravel"]
        }
        
        for lang in languages:
            if lang in language_framework_map:
                frameworks.extend(language_framework_map[lang])
        
        return frameworks


class FileScanExecutionAgent(ExecutionAgent):
    """Agent thực thi intelligent file scanning"""
    
    def __init__(self):
        super().__init__(name="FileScanExecutionAgent")
    
    def _enhance_results(self, result: Dict[str, Any], optimization: Dict[str, Any]) -> Dict[str, Any]:
        """Enhance scan results với intelligence context"""
        if not isinstance(result, dict):
            return result
        
        enhanced_result = result.copy()
        optimization_data = optimization.get("optimization", {})
        
        # Add enhanced metadata
        enhanced_result["intelligent_enhancements"] = {
            "strategy_applied": optimization_data.get("strategy", "standard"),
            "execution_mode": optimization_data.get("execution_mode", "normal"),
            "risk_level": optimization_data.get("risk_level", "unknown"),
            "analysis_timestamp": self._get_timestamp()
        }
        
        # Prioritize findings if available
        if "detailed_results" in enhanced_result and isinstance(enhanced_result["detailed_results"], list):
            enhanced_result["detailed_results"] = self._prioritize_findings(
                enhanced_result["detailed_results"], 
                optimization_data.get("risk_level", "low")
            )
        
        return enhanced_result
    
    def _prioritize_findings(self, findings: List[Dict], risk_level: str) -> List[Dict]:
        """Prioritize findings based on risk level"""
        if not findings:
            return findings
        
        # Define severity priorities
        severity_order = {"error": 0, "warning": 1, "info": 2, "unknown": 3}
        
        # Sort findings
        sorted_findings = sorted(
            findings, 
            key=lambda x: severity_order.get(
                x.get("extra", {}).get("severity", "unknown").lower(), 
                999
            )
        )
        
        # For high risk level, limit to critical findings
        if risk_level == "high":
            critical_findings = [f for f in sorted_findings 
                               if f.get("extra", {}).get("severity", "").lower() in ["error", "warning"]]
            if critical_findings:
                return critical_findings
        
        return sorted_findings


# ============================================================================
# QUICK CHECK WORKFLOW AGENTS
# ============================================================================

class QuickCheckAnalysisAgent(AnalysisAgent):
    """Agent phân tích code snippet cho quick check"""
    
    def __init__(self):
        super().__init__(name="QuickCheckAnalysisAgent")
    
    def _determine_requirements(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        """Xác định yêu cầu dựa trên code snippet"""
        args = inputs.get("args", [])
        if not args or len(args) < 2:
            return {"approach": "standard", "complexity": "unknown"}
        
        try:
            # Extract code and language
            code = args[0]
            language = args[1].lower() if len(args) > 1 else "unknown"
            
            # Analyze code complexity
            complexity_analysis = self._analyze_code_complexity(code)
            
            # Analyze language patterns
            language_analysis = self._analyze_language_patterns(code, language)
            
            return {
                "approach": self._determine_approach(complexity_analysis, language_analysis),
                "complexity": complexity_analysis.get("complexity_level", "medium"),
                "code_analysis": complexity_analysis,
                "language_analysis": language_analysis,
                "optimization_hints": {
                    "focus_on_imports": language_analysis.get("has_imports", False),
                    "focus_on_auth": language_analysis.get("auth_related", False),
                    "focus_on_db": language_analysis.get("db_related", False),
                    "execution_mode": "deep" if complexity_analysis.get("complexity_level") == "high" else "normal"
                }
            }
            
        except Exception as e:
            logger.error(f"Code analysis failed: {e}")
            return {"approach": "standard", "complexity": "unknown", "error": str(e)}
    
    def _analyze_code_complexity(self, code: str) -> Dict[str, Any]:
        """Phân tích complexity của code snippet"""
        if not code:
            return {"complexity_level": "low", "line_count": 0}
        
        # Count lines
        lines = code.split("\n")
        line_count = len(lines)
        
        # Simple complexity metrics
        function_count = len(re.findall(r"def\s+\w+\s*\(", code))
        class_count = len(re.findall(r"class\s+\w+", code))
        branch_count = len(re.findall(r"if|else|elif|for|while|try|except", code))
        
        # Calculate complexity
        complexity_score = function_count * 2 + class_count * 3 + branch_count + line_count // 10
        
        if complexity_score > 10:
            complexity_level = "high"
        elif complexity_score > 5:
            complexity_level = "medium"
        else:
            complexity_level = "low"
        
        return {
            "complexity_level": complexity_level,
            "complexity_score": complexity_score,
            "line_count": line_count,
            "function_count": function_count,
            "class_count": class_count,
            "branch_count": branch_count
        }
    
    def _analyze_language_patterns(self, code: str, language: str) -> Dict[str, Any]:
        """Phân tích language-specific patterns"""
        if not code:
            return {"language": language}
        
        # Common patterns
        has_imports = False
        auth_related = False
        db_related = False
        
        # Language specific patterns
        if language == "python":
            has_imports = bool(re.findall(r"import\s+\w+|from\s+\w+\s+import", code))
            auth_related = bool(re.findall(r"auth|login|password|user|session", code.lower()))
            db_related = bool(re.findall(r"sql|query|cursor|execute|select|insert|update|delete", code.lower()))
        
        elif language in ["javascript", "typescript"]:
            has_imports = bool(re.findall(r"import\s+|require\(", code))
            auth_related = bool(re.findall(r"auth|login|password|user|token|jwt", code.lower()))
            db_related = bool(re.findall(r"sql|query|database|mongo|find|update|delete", code.lower()))
        
        return {
            "language": language,
            "has_imports": has_imports,
            "auth_related": auth_related,
            "db_related": db_related,
            "risk_areas": [area for area, present in {
                "authentication": auth_related,
                "database": db_related
            }.items() if present]
        }
    
    def _determine_approach(self, complexity: Dict[str, Any], language: Dict[str, Any]) -> str:
        """Xác định approach dựa trên phân tích"""
        if complexity.get("complexity_level") == "high":
            return "comprehensive"
        elif language.get("auth_related") or language.get("db_related"):
            return "targeted"
        else:
            return "standard"


class QuickCheckOptimizationAgent(OptimizationAgent):
    """Agent tối ưu hóa quick security check"""
    
    def __init__(self):
        super().__init__(name="QuickCheckOptimizationAgent")
    
    def _create_optimization_strategy(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Tạo optimization strategy dựa trên phân tích"""
        requirements = analysis.get("requirements", {})
        approach = requirements.get("approach", "standard")
        complexity = requirements.get("complexity", "medium")
        code_analysis = requirements.get("code_analysis", {})
        language_analysis = requirements.get("language_analysis", {})
        
        # Define rule selection
        rule_selection = ["security-audit"]  # Default
        
        # Add language specific rules
        language = language_analysis.get("language", "unknown")
        if language != "unknown":
            rule_selection.append(language)
        
        # Add specific focus areas
        if language_analysis.get("auth_related"):
            rule_selection.append("auth")
        if language_analysis.get("db_related"):
            rule_selection.append("injection")
        
        return {
            "strategy": approach,
            "rule_selection": rule_selection,
            "scan_depth": "deep" if complexity == "high" else "normal",
            "focus_areas": language_analysis.get("risk_areas", [])
        }


class QuickCheckExecutionAgent(ExecutionAgent):
    """Agent thực thi intelligent quick check"""
    
    def __init__(self):
        super().__init__(name="QuickCheckExecutionAgent")
    
    def _enhance_results(self, result: Dict[str, Any], optimization: Dict[str, Any]) -> Dict[str, Any]:
        """Enhance quick check results với intelligence context"""
        if not isinstance(result, dict):
            return result
        
        enhanced_result = result.copy()
        optimization_data = optimization.get("optimization", {})
        
        # Add enhanced insights
        enhanced_result["intelligent_insights"] = {
            "strategy": optimization_data.get("strategy", "standard"),
            "scan_depth": optimization_data.get("scan_depth", "normal"),
            "focus_areas": optimization_data.get("focus_areas", []),
            "notes": self._generate_advice(result, optimization_data),
            "timestamp": self._get_timestamp()
        }
        
        return enhanced_result
    
    def _generate_advice(self, result: Dict[str, Any], optimization: Dict[str, Any]) -> List[str]:
        """Generate advice based on results and optimization strategy"""
        advice_list = []
        findings_count = result.get("total_findings", 0)
        focus_areas = optimization.get("focus_areas", [])
        
        if findings_count > 0:
            advice_list.append(f"Found {findings_count} issues that should be addressed")
            
            if "authentication" in focus_areas:
                advice_list.append("Pay special attention to authentication vulnerabilities")
            
            if "database" in focus_areas:
                advice_list.append("Check for SQL injection and data access issues")
                
        else:
            advice_list.append("No issues found, but continue following security best practices")
            
        return advice_list 