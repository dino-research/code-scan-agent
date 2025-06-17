"""
Intelligent Workflow Orchestration

Module này triển khai Sequential Workflow Agents cho các tính năng intelligent.
Mỗi workflow sẽ thực hiện theo 3 bước:
1. Analysis - Phân tích context và yêu cầu
2. Optimization - Tối ưu hóa approach và parameters
3. Execution - Thực thi với intelligent enhancements

Based on: https://google.github.io/adk-docs/agents/workflow-agents/
"""

import logging
from typing import Dict, List, Any, Optional, Callable
from functools import wraps

from .agents import AnalysisAgent, OptimizationAgent, ExecutionAgent

logger = logging.getLogger(__name__)

# ============================================================================
# SEQUENTIAL WORKFLOW ORCHESTRATOR
# ============================================================================

class IntelligentWorkflowOrchestrator:
    """
    Orchestrator chính triển khai Sequential Workflow pattern
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
                    "intelligence_level": "advanced" if all([
                        analysis.get("status") == "success",
                        optimization.get("status") == "success",
                        execution.get("intelligence_applied", False)
                    ]) else "basic"
                }
            }
        
        return result
    
    def _fallback_execution(self, original_function, *args, **kwargs) -> Dict[str, Any]:
        """Execute original function nếu không có intelligent workflow"""
        logger.info(f"Using fallback execution for {original_function.__name__}")
        try:
            result = original_function(*args, **kwargs)
            
            # Add basic workflow metadata
            if isinstance(result, dict):
                result["workflow_metadata"] = {
                    "workflow_type": "traditional",
                    "intelligence_features": {
                        "context_analysis": False,
                        "parameter_optimization": False,
                        "enhanced_execution": False
                    }
                }
            
            return result
        except Exception as e:
            logger.error(f"Fallback execution failed: {e}")
            return {
                "status": "error",
                "error": f"Execution failed: {str(e)}",
                "workflow_type": "fallback_failed"
            }


# ============================================================================
# BASE WORKFLOW CLASS
# ============================================================================

class BaseWorkflow:
    """Base class for all workflows"""
    
    def __init__(self, analysis_agent=None, optimization_agent=None, execution_agent=None):
        self.analysis_agent = analysis_agent or AnalysisAgent(f"{self.__class__.__name__}Analysis")
        self.optimization_agent = optimization_agent or OptimizationAgent(f"{self.__class__.__name__}Optimization")
        self.execution_agent = execution_agent or ExecutionAgent(f"{self.__class__.__name__}Execution")
    
    def analyze_context(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        """Interface for context analysis"""
        return self.analysis_agent.analyze_context(inputs)
    
    def optimize_approach(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Interface for approach optimization"""
        return self.optimization_agent.optimize_approach(analysis)
    
    def execute_with_intelligence(self, optimization: Dict[str, Any], original_function, *args, **kwargs) -> Dict[str, Any]:
        """Interface for intelligent execution"""
        return self.execution_agent.execute_with_intelligence(optimization, original_function, *args, **kwargs)


# ============================================================================
# SPECIFIC WORKFLOWS
# ============================================================================

class FileScanWorkflow(BaseWorkflow):
    """Workflow for file scanning functions"""
    
    def __init__(self):
        from .workflow_agents import FileScanAnalysisAgent, FileScanOptimizationAgent, FileScanExecutionAgent
        super().__init__(
            FileScanAnalysisAgent(), 
            FileScanOptimizationAgent(),
            FileScanExecutionAgent()
        )


class QuickCheckWorkflow(BaseWorkflow):
    """Workflow for quick security check functions"""
    
    def __init__(self):
        from .workflow_agents import QuickCheckAnalysisAgent, QuickCheckOptimizationAgent, QuickCheckExecutionAgent
        super().__init__(
            QuickCheckAnalysisAgent(), 
            QuickCheckOptimizationAgent(),
            QuickCheckExecutionAgent()
        )


class CustomRuleWorkflow(BaseWorkflow):
    """Workflow for custom rule scanning"""
    pass


class CodeStructureWorkflow(BaseWorkflow):
    """Workflow for code structure analysis"""
    pass


class ArchitectureWorkflow(BaseWorkflow):
    """Workflow for project architecture analysis"""
    pass


class LanguagesWorkflow(BaseWorkflow):
    """Workflow for supported languages"""
    pass


class SchemaWorkflow(BaseWorkflow):
    """Workflow for rule schema"""
    pass


# Decorator to apply intelligent workflows
def apply_intelligent_workflow(tool_name: str):
    """
    Decorator để áp dụng intelligent workflow cho bất kỳ function nào
    
    Args:
        tool_name: Tên của tool trong orchestrator
    """
    def decorator(original_function):
        orchestrator = IntelligentWorkflowOrchestrator()
        
        @wraps(original_function)
        def wrapper(*args, **kwargs):
            return orchestrator.execute_intelligent_workflow(tool_name, original_function, *args, **kwargs)
        
        return wrapper
    
    return decorator