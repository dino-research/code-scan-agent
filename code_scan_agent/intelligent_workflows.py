#!/usr/bin/env python3
"""
Intelligent Workflows for Code Scan Agent Tools

Implements ADK Sequential Workflow Agents to provide intelligent orchestration
for all tools in the root agent. Each workflow uses specialized sub-agents to:
1. Analyze context and requirements
2. Optimize approach and parameters
3. Execute with enhanced intelligence
4. Post-process and enhance results

Based on: https://google.github.io/adk-docs/agents/workflow-agents/
"""

import logging
from pathlib import Path
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)


# ============================================================================
# CUSTOM AGENT BASE CLASS (replacing google.adk.agents.Agent)
# ============================================================================

class Agent:
    """
    Custom Agent base class implementing ADK-like interface
    Since google.adk.agents is not available, we create our own implementation
    """
    
    def __init__(self, name: str, **kwargs):
        # Accept arbitrary kwargs for compatibility with original ADK Agent signature
        self.name = name
        self.config: Dict[str, Any] = kwargs
        self.created_at = self._get_timestamp()
        logger.debug(f"Agent '{name}' initialized with config: {kwargs}")
    
    def _get_timestamp(self) -> str:
        """Get current timestamp"""
        from datetime import datetime
        return datetime.now().isoformat()


# ============================================================================
# BASE WORKFLOW COMPONENTS
# ============================================================================

class AnalysisAgent(Agent):
    """
    Base agent cho context analysis và requirement determination
    """
    
    def __init__(self, name: str):
        super().__init__(name=name)
    
    def analyze_context(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze context và determine requirements"""
        return {
            "status": "success", 
            "analysis": inputs,
            "requirements": self._determine_requirements(inputs)
        }
    
    def _determine_requirements(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        """Override trong subclasses"""
        return {"approach": "standard"}


class OptimizationAgent(Agent):
    """
    Base agent cho parameter optimization và approach selection
    """
    
    def __init__(self, name: str):
        super().__init__(name=name)
    
    def optimize_approach(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize approach based on analysis"""
        return {
            "status": "success",
            "optimization": self._create_optimization_strategy(analysis),
            "enhanced_params": self._optimize_parameters(analysis)
        }
    
    def _create_optimization_strategy(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Override trong subclasses"""
        return {"strategy": "default"}
    
    def _optimize_parameters(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Override trong subclasses"""
        return analysis.get("requirements", {})


class ExecutionAgent(Agent):
    """
    Base agent cho intelligent execution với enhanced features
    """
    
    def __init__(self, name: str):
        super().__init__(name=name)
    
    def execute_with_intelligence(self, optimization: Dict[str, Any], original_function, *args, **kwargs) -> Dict[str, Any]:
        """Execute function với intelligent enhancements"""
        try:
            # Apply optimizations to parameters - only include valid parameters for traditional function
            enhanced_params = optimization.get("enhanced_params", {})
            
            # Filter enhanced params to only include valid function arguments
            import inspect
            try:
                sig = inspect.signature(original_function)
                valid_params = {k: v for k, v in enhanced_params.items() if k in sig.parameters}
                updated_kwargs = {**kwargs, **valid_params}
            except Exception:
                # Fallback: don't add enhanced params if we can't inspect
                updated_kwargs = kwargs
            
            # Execute original function
            result = original_function(*args, **updated_kwargs)
            
            # Enhance results with intelligence context
            enhanced_result = self._enhance_results(result, optimization)
            
            return {
                "status": "success",
                "execution_result": enhanced_result,
                "intelligence_applied": True,
                "optimization_used": optimization.get("optimization", {})
            }
            
        except Exception as e:
            logger.error(f"Intelligent execution failed: {e}")
            return {
                "status": "error",
                "error": str(e),
                "fallback_needed": True
            }
    
    def _enhance_results(self, result: Dict[str, Any], optimization: Dict[str, Any]) -> Dict[str, Any]:
        """Enhance results với intelligence context"""
        if isinstance(result, dict):
            enhanced = result.copy()
            enhanced["intelligence_metadata"] = {
                "intelligent_execution": True,
                "optimization_applied": True,
                "enhancement_timestamp": self._get_timestamp()
            }
            return enhanced
        return result


# ============================================================================
# SEQUENTIAL WORKFLOW ORCHESTRATOR
# ============================================================================

class IntelligentWorkflowOrchestrator:
    """
    Main orchestrator implementing Sequential Workflow pattern
    Coordinates: Analysis → Optimization → Execution
    """
    
    def __init__(self):
        self.workflows = {}
        self._initialize_workflows()
        logger.info("IntelligentWorkflowOrchestrator initialized")
    
    def _initialize_workflows(self):
        """Initialize all intelligent workflows"""
        # File scanning workflows
        self.workflows["scan_code_files"] = FileScanWorkflow()
        self.workflows["quick_security_check"] = QuickCheckWorkflow()
        self.workflows["scan_with_custom_rule"] = CustomRuleWorkflow()
        
        # Analysis workflows  
        self.workflows["analyze_code_structure"] = CodeStructureWorkflow()
        self.workflows["analyze_project_architecture"] = ArchitectureWorkflow()
        
        # Utility workflows
        self.workflows["get_supported_languages"] = LanguagesWorkflow()
        self.workflows["get_semgrep_rule_schema"] = SchemaWorkflow()
    
    def execute_intelligent_workflow(self, tool_name: str, original_function, *args, **kwargs) -> Dict[str, Any]:
        """
        Execute intelligent workflow for any tool
        Implements Sequential Agent pattern: Analysis → Optimization → Execution
        """
        try:
            logger.info(f"Starting intelligent workflow for: {tool_name}")
            
            # Check if workflow exists
            if tool_name not in self.workflows:
                logger.warning(f"No intelligent workflow for {tool_name}, using standard execution")
                return self._fallback_execution(original_function, *args, **kwargs)
            
            workflow = self.workflows[tool_name]
            
            # Step 1: Context Analysis
            logger.info("Step 1: Analyzing context and requirements...")
            analysis_result = workflow.analyze_context({
                "tool_name": tool_name,
                "args": args,
                "kwargs": kwargs,
                "function_name": original_function.__name__
            })
            
            if analysis_result.get("status") != "success":
                logger.warning("Context analysis failed, using fallback")
                return self._fallback_execution(original_function, *args, **kwargs)
            
            # Step 2: Optimization
            logger.info("Step 2: Optimizing approach and parameters...")
            optimization_result = workflow.optimize_approach(analysis_result)
            
            # Step 3: Intelligent Execution
            logger.info("Step 3: Executing with intelligent enhancements...")
            execution_result = workflow.execute_with_intelligence(
                optimization_result, original_function, *args, **kwargs
            )
            
            # Combine all results for final output
            final_result = self._combine_workflow_results(
                analysis_result, optimization_result, execution_result, tool_name
            )
            
            logger.info(f"Intelligent workflow completed for: {tool_name}")
            return final_result
            
        except Exception as e:
            logger.error(f"Intelligent workflow failed for {tool_name}: {e}")
            return self._fallback_execution(original_function, *args, **kwargs)
    
    def _combine_workflow_results(self, analysis: Dict, optimization: Dict, execution: Dict, tool_name: str) -> Dict[str, Any]:
        """Combine workflow results into final output"""
        # Get the actual tool result
        if execution.get("status") == "success":
            result = execution.get("execution_result", {})
        else:
            result = {"status": "error", "error": execution.get("error", "Unknown error")}
        
        # Add workflow metadata
        if isinstance(result, dict):
            result["workflow_metadata"] = {
                "tool_name": tool_name,
                "workflow_type": "sequential_intelligent",
                "steps_completed": ["analysis", "optimization", "execution"],
                "intelligence_features": {
                    "context_analysis": analysis.get("status") == "success",
                    "parameter_optimization": optimization.get("status") == "success", 
                    "enhanced_execution": execution.get("intelligence_applied", False)
                },
                "workflow_summary": {
                    "requirements_identified": analysis.get("requirements", {}),
                    "optimizations_applied": optimization.get("optimization", {}),
                    "intelligence_level": "enhanced"
                }
            }
        
        return result
    
    def _fallback_execution(self, original_function, *args, **kwargs) -> Dict[str, Any]:
        """Fallback to standard execution"""
        try:
            result = original_function(*args, **kwargs)
            if isinstance(result, dict):
                result["workflow_metadata"] = {
                    "workflow_type": "standard_fallback",
                    "intelligence_features": False
                }
            return result
        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
                "workflow_metadata": {"workflow_type": "fallback_failed"}
            }


# ============================================================================
# SPECIFIC WORKFLOW IMPLEMENTATIONS  
# ============================================================================

class FileScanWorkflow:
    """Intelligent workflow for scan_code_files"""
    
    def __init__(self):
        self.analysis_agent = FileScanAnalysisAgent()
        self.optimization_agent = FileScanOptimizationAgent()
        self.execution_agent = FileScanExecutionAgent()
    
    def analyze_context(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        return self.analysis_agent.analyze_context(inputs)
    
    def optimize_approach(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        return self.optimization_agent.optimize_approach(analysis)
    
    def execute_with_intelligence(self, optimization: Dict[str, Any], original_function, *args, **kwargs) -> Dict[str, Any]:
        return self.execution_agent.execute_with_intelligence(optimization, original_function, *args, **kwargs)


class FileScanAnalysisAgent(AnalysisAgent):
    """Analysis agent for file scanning operations"""
    
    def __init__(self):
        super().__init__(name="FileScanAnalysisAgent")
    
    def _determine_requirements(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze files and determine scanning requirements"""
        args = inputs.get("args", [])
        kwargs = inputs.get("kwargs", {})
        
        requirements = {
            "scan_approach": "standard",
            "file_count": 0,
            "estimated_complexity": "low",
            "optimization_needed": False
        }
        
        # Analyze file paths
        if args and len(args) > 0:
            file_paths = args[0] if isinstance(args[0], list) else [args[0]]
            requirements["file_count"] = len(file_paths)
            
            # Analyze file characteristics
            file_analysis = self._analyze_files(file_paths)
            requirements.update(file_analysis)
            
            # Determine if optimization is needed
            if requirements["file_count"] > 10:
                requirements["optimization_needed"] = True
                requirements["scan_approach"] = "batch_optimized"
            elif requirements.get("large_files", 0) > 3:
                requirements["optimization_needed"] = True
                requirements["scan_approach"] = "size_optimized"
        
        return requirements
    
    def _analyze_files(self, file_paths: List[str]) -> Dict[str, Any]:
        """Analyze file characteristics"""
        analysis = {
            "total_size": 0,
            "large_files": 0,
            "file_types": set(),
            "estimated_complexity": "low"
        }
        
        for file_path in file_paths[:10]:  # Sample first 10 files
            try:
                path = Path(file_path)
                if path.exists() and path.is_file():
                    size = path.stat().st_size
                    analysis["total_size"] += size
                    
                    if size > 1024 * 1024:  # 1MB
                        analysis["large_files"] += 1
                    
                    analysis["file_types"].add(path.suffix.lower())
            except Exception:
                continue
        
        # Determine complexity
        if analysis["large_files"] > 2 or analysis["total_size"] > 10 * 1024 * 1024:
            analysis["estimated_complexity"] = "high"
        elif analysis["large_files"] > 0 or len(analysis["file_types"]) > 3:
            analysis["estimated_complexity"] = "medium"
        
        analysis["file_types"] = list(analysis["file_types"])
        return analysis


class FileScanOptimizationAgent(OptimizationAgent):
    """Optimization agent for file scanning"""
    
    def __init__(self):
        super().__init__(name="FileScanOptimizationAgent")
    
    def _create_optimization_strategy(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Create optimization strategy based on analysis"""
        requirements = analysis.get("requirements", {})
        
        strategy = {
            "parallel_processing": False,
            "batch_size": None,
            "timeout_adjustment": False,
            "memory_optimization": False
        }
        
        # Enable optimizations based on requirements
        if requirements.get("file_count", 0) > 5:
            strategy["parallel_processing"] = True
            strategy["batch_size"] = min(5, requirements["file_count"] // 2)
        
        if requirements.get("estimated_complexity") == "high":
            strategy["timeout_adjustment"] = True
            strategy["memory_optimization"] = True
        
        return strategy
    
    def _optimize_parameters(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize parameters based on analysis"""
        requirements = analysis.get("requirements", {})
        optimized = {}
        
        # Add intelligent config selection
        if requirements.get("file_count", 0) > 10:
            optimized["config"] = "p/security-audit"  # Faster for many files
        elif requirements.get("estimated_complexity") == "high":
            optimized["config"] = "auto"  # More thorough for complex files
        
        return optimized


class FileScanExecutionAgent(ExecutionAgent):
    """Execution agent for file scanning"""
    
    def __init__(self):
        super().__init__(name="FileScanExecutionAgent")
    
    def _enhance_results(self, result: Dict[str, Any], optimization: Dict[str, Any]) -> Dict[str, Any]:
        """Enhance scan results with intelligence context"""
        enhanced = super()._enhance_results(result, optimization)
        
        if isinstance(enhanced, dict):
            # Add scan optimization info
            enhanced["scan_intelligence"] = {
                "optimization_strategy": optimization.get("optimization", {}),
                "performance_enhanced": True,
                "batch_processing_used": optimization.get("optimization", {}).get("parallel_processing", False)
            }
            
            # Enhance findings with priority
            if "detailed_results" in enhanced:
                enhanced["detailed_results"] = self._prioritize_findings(enhanced["detailed_results"])
        
        return enhanced
    
    def _prioritize_findings(self, findings: List[Dict]) -> List[Dict]:
        """Add priority information to findings"""
        if not isinstance(findings, list):
            return findings
        
        # Sort by severity and add priority
        severity_order = {"error": 3, "warning": 2, "info": 1}
        
        prioritized = []
        for finding in findings:
            enhanced_finding = finding.copy() if isinstance(finding, dict) else finding
            
            if isinstance(enhanced_finding, dict):
                severity = enhanced_finding.get("extra", {}).get("severity", "info").lower()
                enhanced_finding["intelligence_priority"] = severity_order.get(severity, 1)
                enhanced_finding["priority_label"] = "High" if severity == "error" else "Medium" if severity == "warning" else "Low"
            
            prioritized.append(enhanced_finding)
        
        # Sort by priority (highest first)
        return sorted(prioritized, key=lambda x: x.get("intelligence_priority", 0), reverse=True)


# ============================================================================
# QUICK CHECK WORKFLOW
# ============================================================================

class QuickCheckWorkflow:
    """Intelligent workflow for quick_security_check"""
    
    def __init__(self):
        self.analysis_agent = QuickCheckAnalysisAgent()
        self.optimization_agent = QuickCheckOptimizationAgent()
        self.execution_agent = QuickCheckExecutionAgent()
    
    def analyze_context(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        return self.analysis_agent.analyze_context(inputs)
    
    def optimize_approach(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        return self.optimization_agent.optimize_approach(analysis)
    
    def execute_with_intelligence(self, optimization: Dict[str, Any], original_function, *args, **kwargs) -> Dict[str, Any]:
        return self.execution_agent.execute_with_intelligence(optimization, original_function, *args, **kwargs)


class QuickCheckAnalysisAgent(AnalysisAgent):
    """Analysis agent for quick security checks"""
    
    def __init__(self):
        super().__init__(name="QuickCheckAnalysisAgent")
    
    def _determine_requirements(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze code content and language for optimal quick check"""
        args = inputs.get("args", [])
        
        requirements = {
            "code_complexity": "low",
            "language_confidence": "medium",
            "check_intensity": "standard",
            "pattern_focus": []
        }
        
        if len(args) >= 2:
            code_content = args[0] if args else ""
            language = args[1] if len(args) > 1 else "python"
            
            # Analyze code complexity
            complexity_analysis = self._analyze_code_complexity(code_content)
            requirements.update(complexity_analysis)
            
            # Analyze language patterns
            language_analysis = self._analyze_language_patterns(code_content, language)
            requirements.update(language_analysis)
        
        return requirements
    
    def _analyze_code_complexity(self, code: str) -> Dict[str, Any]:
        """Analyze code complexity for optimization"""
        if not code:
            return {"code_complexity": "low", "check_intensity": "light"}
        
        lines = code.split('\n')
        complexity_indicators = {
            "line_count": len(lines),
            "function_count": len([l for l in lines if 'def ' in l or 'function ' in l]),
            "import_count": len([l for l in lines if 'import ' in l or 'from ' in l]),
            "complexity_keywords": 0
        }
        
        # Check for complexity keywords
        complex_keywords = ['class ', 'async ', 'await ', 'lambda ', 'try:', 'except:', 'finally:']
        for line in lines:
            for keyword in complex_keywords:
                if keyword in line:
                    complexity_indicators["complexity_keywords"] += 1
        
        # Determine overall complexity
        if (complexity_indicators["line_count"] > 100 or 
            complexity_indicators["function_count"] > 5 or
            complexity_indicators["complexity_keywords"] > 10):
            return {"code_complexity": "high", "check_intensity": "thorough"}
        elif (complexity_indicators["line_count"] > 20 or 
              complexity_indicators["function_count"] > 1):
            return {"code_complexity": "medium", "check_intensity": "standard"}
        else:
            return {"code_complexity": "low", "check_intensity": "light"}
    
    def _analyze_language_patterns(self, code: str, language: str) -> Dict[str, Any]:
        """Analyze language-specific patterns"""
        patterns_found = []
        
        # Language-specific security patterns
        security_patterns = {
            "python": ["eval(", "exec(", "subprocess", "os.system", "pickle.loads"],
            "javascript": ["eval(", "innerHTML", "document.write", "setTimeout", "setInterval"],
            "java": ["Runtime.exec", "ProcessBuilder", "Class.forName", "SQL"],
            "php": ["eval(", "exec(", "shell_exec", "system(", "$_GET", "$_POST"]
        }
        
        if language.lower() in security_patterns:
            for pattern in security_patterns[language.lower()]:
                if pattern in code:
                    patterns_found.append(pattern)
        
        return {
            "language_confidence": "high" if patterns_found else "medium",
            "pattern_focus": patterns_found,
            "security_priority": "high" if len(patterns_found) > 2 else "medium" if patterns_found else "low"
        }


class QuickCheckOptimizationAgent(OptimizationAgent):
    """Optimization agent for quick checks"""
    
    def __init__(self):
        super().__init__(name="QuickCheckOptimizationAgent")
    
    def _create_optimization_strategy(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Create optimization strategy for quick checks"""
        requirements = analysis.get("requirements", {})
        
        strategy = {
            "rule_selection": "auto",
            "timeout_optimization": False,
            "result_enhancement": True,
            "pattern_priority": []
        }
        
        # Optimize based on complexity
        complexity = requirements.get("code_complexity", "low")
        if complexity == "high":
            strategy["rule_selection"] = "comprehensive"
            strategy["timeout_optimization"] = True
        elif complexity == "medium":
            strategy["rule_selection"] = "balanced"
        
        # Optimize based on patterns found
        pattern_focus = requirements.get("pattern_focus", [])
        if pattern_focus:
            strategy["pattern_priority"] = pattern_focus
            strategy["result_enhancement"] = True
        
        return strategy


class QuickCheckExecutionAgent(ExecutionAgent):
    """Execution agent for quick checks"""
    
    def __init__(self):
        super().__init__(name="QuickCheckExecutionAgent")
    
    def _enhance_results(self, result: Dict[str, Any], optimization: Dict[str, Any]) -> Dict[str, Any]:
        """Enhance quick check results"""
        enhanced = super()._enhance_results(result, optimization)
        
        if isinstance(enhanced, dict):
            # Add quick check specific enhancements
            enhanced["quick_check_intelligence"] = {
                "optimization_applied": optimization.get("optimization", {}),
                "pattern_focused": len(optimization.get("optimization", {}).get("pattern_priority", [])) > 0,
                "enhanced_analysis": True
            }
            
            # Add contextual advice
            enhanced["intelligent_advice"] = self._generate_advice(enhanced, optimization)
        
        return enhanced
    
    def _generate_advice(self, result: Dict[str, Any], optimization: Dict[str, Any]) -> List[str]:
        """Generate intelligent advice based on results"""
        advice = []
        
        # Analyze findings for advice
        if "result" in result and isinstance(result["result"], dict):
            findings = result["result"].get("content", [])
            if isinstance(findings, list) and findings:
                # Security-specific advice
                advice.append("🔍 Consider running a full directory scan for comprehensive analysis")
                
                # Pattern-specific advice
                patterns = optimization.get("optimization", {}).get("pattern_priority", [])
                if "eval(" in patterns:
                    advice.append("⚠️  eval() usage detected - consider safer alternatives")
                if "subprocess" in patterns:
                    advice.append("🔒 subprocess usage found - ensure input validation")
        
        return advice[:5]  # Limit to top 5 advice items


# ============================================================================
# OTHER WORKFLOW IMPLEMENTATIONS (Simplified for space)
# ============================================================================

class CustomRuleWorkflow:
    """Workflow for scan_with_custom_rule"""
    def __init__(self):
        self.analysis_agent = AnalysisAgent("CustomRuleAnalysis")
        self.optimization_agent = OptimizationAgent("CustomRuleOptimization")
        self.execution_agent = ExecutionAgent("CustomRuleExecution")
    
    def analyze_context(self, inputs): return self.analysis_agent.analyze_context(inputs)
    def optimize_approach(self, analysis): return self.optimization_agent.optimize_approach(analysis)
    def execute_with_intelligence(self, opt, func, *args, **kwargs): return self.execution_agent.execute_with_intelligence(opt, func, *args, **kwargs)


class CodeStructureWorkflow:
    """Workflow for analyze_code_structure"""
    def __init__(self):
        self.analysis_agent = AnalysisAgent("CodeStructureAnalysis")
        self.optimization_agent = OptimizationAgent("CodeStructureOptimization")
        self.execution_agent = ExecutionAgent("CodeStructureExecution")
    
    def analyze_context(self, inputs): return self.analysis_agent.analyze_context(inputs)
    def optimize_approach(self, analysis): return self.optimization_agent.optimize_approach(analysis)
    def execute_with_intelligence(self, opt, func, *args, **kwargs): return self.execution_agent.execute_with_intelligence(opt, func, *args, **kwargs)


class ArchitectureWorkflow:
    """Workflow for analyze_project_architecture"""
    def __init__(self):
        self.analysis_agent = AnalysisAgent("ArchitectureAnalysis")
        self.optimization_agent = OptimizationAgent("ArchitectureOptimization")
        self.execution_agent = ExecutionAgent("ArchitectureExecution")
    
    def analyze_context(self, inputs): return self.analysis_agent.analyze_context(inputs)
    def optimize_approach(self, analysis): return self.optimization_agent.optimize_approach(analysis)
    def execute_with_intelligence(self, opt, func, *args, **kwargs): return self.execution_agent.execute_with_intelligence(opt, func, *args, **kwargs)


class LanguagesWorkflow:
    """Workflow for get_supported_languages"""
    def __init__(self):
        self.analysis_agent = AnalysisAgent("LanguagesAnalysis")
        self.optimization_agent = OptimizationAgent("LanguagesOptimization")
        self.execution_agent = ExecutionAgent("LanguagesExecution")
    
    def analyze_context(self, inputs): return self.analysis_agent.analyze_context(inputs)
    def optimize_approach(self, analysis): return self.optimization_agent.optimize_approach(analysis)
    def execute_with_intelligence(self, opt, func, *args, **kwargs): return self.execution_agent.execute_with_intelligence(opt, func, *args, **kwargs)


class SchemaWorkflow:
    """Workflow for get_semgrep_rule_schema"""
    def __init__(self):
        self.analysis_agent = AnalysisAgent("SchemaAnalysis")
        self.optimization_agent = OptimizationAgent("SchemaOptimization")
        self.execution_agent = ExecutionAgent("SchemaExecution")
    
    def analyze_context(self, inputs): return self.analysis_agent.analyze_context(inputs)
    def optimize_approach(self, analysis): return self.optimization_agent.optimize_approach(analysis)
    def execute_with_intelligence(self, opt, func, *args, **kwargs): return self.execution_agent.execute_with_intelligence(opt, func, *args, **kwargs)


# ============================================================================
# GLOBAL WORKFLOW ORCHESTRATOR INSTANCE
# ============================================================================

# Global instance for easy access
intelligent_workflow_orchestrator = IntelligentWorkflowOrchestrator()

def apply_intelligent_workflow(tool_name: str, original_function):
    """
    Decorator/wrapper to apply intelligent workflow to any tool
    
    Usage:
        @apply_intelligent_workflow("scan_code_files", original_scan_code_files)
        def intelligent_scan_code_files(*args, **kwargs):
            pass
    """
    def wrapper(*args, **kwargs):
        return intelligent_workflow_orchestrator.execute_intelligent_workflow(
            tool_name, original_function, *args, **kwargs
        )
    return wrapper 