"""
Intelligent Workflow Orchestration

Module này triển khai Sequential Workflow Agents cho các tính năng intelligent.
Mỗi workflow sẽ thực hiện theo 3 bước:
1. Analysis - Phân tích context và yêu cầu
2. Optimization - Tối ưu hóa approach và parameters
3. Execution - Thực thi với intelligent enhancements

Enhanced với ADK-compatible context management.
Based on: https://google.github.io/adk-docs/agents/workflow-agents/
Based on: https://google.github.io/adk-docs/context/
"""

import logging
from typing import Dict, List, Any, Optional, Callable
from functools import wraps

from .agents import AnalysisAgent, OptimizationAgent, ExecutionAgent
from .context import WorkflowContext, ContextFactory, ToolContext

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
        Execute intelligent workflow for any tool với ADK-compatible context
        Implements Sequential Agent pattern: Analysis → Optimization → Execution
        """
        # Create workflow context theo ADK patterns
        session_id = ContextFactory.generate_session_id()
        invocation_id = ContextFactory.generate_invocation_id()
        context = ContextFactory.create_workflow_context(session_id, invocation_id, f"workflow_{tool_name}")
        
        try:
            logger.info(f"Starting intelligent workflow for: {tool_name}")
            context.start_step("workflow_initialization")
            
            # Store initial inputs in context state
            context.set_state("tool_name", tool_name)
            context.set_state("function_name", original_function.__name__)
            context.save_artifact("input_args", {"args": args, "kwargs": kwargs}, "application/json")
            
            # Check if workflow exists
            if tool_name not in self.workflows:
                logger.warning(f"No intelligent workflow for {tool_name}, using standard execution")
                return self._fallback_execution_with_context(context, original_function, *args, **kwargs)
            
            workflow = self.workflows[tool_name]
            context.complete_step("workflow_initialization", {"status": "success", "workflow_found": True})
            
            # Step 1: Context Analysis với proper context passing
            context.start_step("analysis")
            logger.info("Step 1: Analyzing context and requirements...")
            
            analysis_inputs = {
                "tool_name": tool_name,
                "args": args,
                "kwargs": kwargs,
                "function_name": original_function.__name__,
                "context": context  # Pass context to workflow
            }
            analysis_result = workflow.analyze_context(analysis_inputs)
            
            if analysis_result.get("status") != "success":
                logger.warning("Context analysis failed, using fallback")
                context.complete_step("analysis", {"status": "failed", "error": "analysis_failed"})
                return self._fallback_execution_with_context(context, original_function, *args, **kwargs)
            
            # Save analysis results as artifact (exclude non-serializable context)
            try:
                serializable_result = {k: v for k, v in analysis_result.items() if k != "context" and k != "tool_context"}
                context.save_artifact("analysis_result", serializable_result, "application/json")
            except Exception as e:
                logger.warning(f"Failed to save analysis artifact: {e}")
                # Continue without saving artifact
            context.complete_step("analysis", analysis_result)
            
            # Step 2: Optimization với context
            context.start_step("optimization")
            logger.info("Step 2: Optimizing approach and parameters...")
            optimization_result = workflow.optimize_approach(analysis_result, context)
            
            # Save optimization results
            context.save_artifact("optimization_result", optimization_result, "application/json")
            context.complete_step("optimization", optimization_result)
            
            # Step 3: Intelligent Execution với context
            context.start_step("execution")
            logger.info("Step 3: Executing with intelligent enhancements...")
            execution_result = workflow.execute_with_intelligence(
                optimization_result, context, original_function, *args, **kwargs
            )
            
            # Save execution results
            context.save_artifact("execution_result", execution_result, "application/json")
            context.complete_step("execution", execution_result)
            
            # Combine all results for final output với context metadata
            final_result = self._combine_workflow_results_with_context(
                context, analysis_result, optimization_result, execution_result, tool_name
            )
            
            logger.info(f"Intelligent workflow completed for: {tool_name}")
            return final_result
            
        except Exception as e:
            logger.error(f"Intelligent workflow failed for {tool_name}: {e}")
            context.complete_step(context.current_step or "unknown", {"status": "error", "error": str(e)})
            return self._fallback_execution_with_context(context, original_function, *args, **kwargs)
        finally:
            # Cleanup context theo ADK pattern
            context.state.clear_temp()
    
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
    
    def _combine_workflow_results_with_context(self, context: WorkflowContext, analysis: Dict, optimization: Dict, execution: Dict, tool_name: str) -> Dict[str, Any]:
        """Combine workflow results với full context metadata"""
        # Get the actual tool result
        if execution.get("status") == "success":
            result = execution.get("execution_result", {})
        else:
            result = {"status": "error", "error": execution.get("error", "Unknown error")}
        
        # Add comprehensive workflow metadata với context info
        if isinstance(result, dict):
            workflow_summary = context.get_workflow_summary()
            
            result["workflow_metadata"] = {
                "tool_name": tool_name,
                "workflow_type": "sequential_intelligent_with_context",
                "steps_completed": workflow_summary["steps_completed"],
                "session_id": context.state.session_id,
                "invocation_id": context.state.invocation_id,
                "intelligence_features": {
                    "context_analysis": analysis.get("status") == "success",
                    "parameter_optimization": optimization.get("status") == "success", 
                    "enhanced_execution": execution.get("intelligence_applied", False),
                    "state_management": True,
                    "artifact_storage": len(context.list_artifacts()) > 0
                },
                "workflow_summary": {
                    "requirements_identified": analysis.get("requirements", {}),
                    "optimizations_applied": optimization.get("optimization", {}),
                    "context_artifacts": context.list_artifacts(),
                    "workflow_duration_ms": workflow_summary["duration_ms"],
                    "intelligence_level": "advanced" if all([
                        analysis.get("status") == "success",
                        optimization.get("status") == "success",
                        execution.get("intelligence_applied", False)
                    ]) else "basic"
                }
            }
            
            # Add context metadata reference
            result["context_metadata"] = {
                "session_id": context.state.session_id,
                "invocation_id": context.state.invocation_id,
                "artifacts_available": context.list_artifacts()
            }
        
        return result
    
    def _fallback_execution_with_context(self, context: WorkflowContext, original_function, *args, **kwargs) -> Dict[str, Any]:
        """Execute original function với context support"""
        logger.info(f"Using fallback execution for {original_function.__name__}")
        try:
            context.start_step("fallback_execution")
            
            # Execute original function
            result = original_function(*args, **kwargs)
            
            # Add context-aware metadata
            if isinstance(result, dict):
                workflow_summary = context.get_workflow_summary()
                
                result["workflow_metadata"] = {
                    "workflow_type": "traditional_with_context",
                    "session_id": context.state.session_id,
                    "invocation_id": context.state.invocation_id,
                    "intelligence_features": {
                        "context_analysis": False,
                        "parameter_optimization": False,
                        "enhanced_execution": False,
                        "state_management": True,
                        "artifact_storage": False
                    },
                    "workflow_duration_ms": workflow_summary["duration_ms"]
                }
                
                result["context_metadata"] = {
                    "session_id": context.state.session_id,
                    "invocation_id": context.state.invocation_id
                }
            
            context.complete_step("fallback_execution", {"status": "success", "type": "traditional"})
            return result
            
        except Exception as e:
            logger.error(f"Fallback execution failed: {e}")
            context.complete_step("fallback_execution", {"status": "error", "error": str(e)})
            
            return {
                "status": "error",
                "error": f"Execution failed: {str(e)}",
                "workflow_type": "fallback_failed_with_context",
                "context_metadata": {
                    "session_id": context.state.session_id,
                    "invocation_id": context.state.invocation_id
                }
            }
    
    def _fallback_execution(self, original_function, *args, **kwargs) -> Dict[str, Any]:
        """Execute original function nếu không có intelligent workflow (legacy)"""
        logger.info(f"Using legacy fallback execution for {original_function.__name__}")
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
    """Base class for all workflows với ADK context support"""
    
    def __init__(self, analysis_agent=None, optimization_agent=None, execution_agent=None):
        self.analysis_agent = analysis_agent or AnalysisAgent(f"{self.__class__.__name__}Analysis")
        self.optimization_agent = optimization_agent or OptimizationAgent(f"{self.__class__.__name__}Optimization")
        self.execution_agent = execution_agent or ExecutionAgent(f"{self.__class__.__name__}Execution")
    
    def analyze_context(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        """Interface for context analysis với context support"""
        # Extract context if provided
        context = inputs.get("context")
        if context and isinstance(context, WorkflowContext):
            # Create tool context for analysis agent
            tool_context = ContextFactory.create_tool_context(context, f"analysis_{self.analysis_agent.name}")
            tool_context.log_tool_usage("analyze_context", {"inputs_keys": list(inputs.keys())})
            
            # Pass context to agent
            inputs_with_context = {**inputs, "tool_context": tool_context}
            result = self.analysis_agent.analyze_context(inputs_with_context)
            
            # Store analysis in context state
            if context and result.get("status") == "success":
                context.set_state("last_analysis", result)
            
            return result
        else:
            # Fallback to original behavior
            return self.analysis_agent.analyze_context(inputs)
    
    def optimize_approach(self, analysis: Dict[str, Any], context: Optional[WorkflowContext] = None) -> Dict[str, Any]:
        """Interface for approach optimization với context support"""
        if context:
            # Create tool context for optimization agent
            tool_context = ContextFactory.create_tool_context(context, f"optimization_{self.optimization_agent.name}")
            tool_context.log_tool_usage("optimize_approach", {"analysis_status": analysis.get("status")})
            
            # Pass context to agent
            result = self.optimization_agent.optimize_approach_with_context(analysis, tool_context)
            
            # Store optimization in context state
            if result.get("status") == "success":
                context.set_state("last_optimization", result)
            
            return result
        else:
            # Fallback to original behavior
            return self.optimization_agent.optimize_approach(analysis)
    
    def execute_with_intelligence(self, optimization: Dict[str, Any], context: Optional[WorkflowContext], original_function, *args, **kwargs) -> Dict[str, Any]:
        """Interface for intelligent execution với context support"""
        if context:
            # Create tool context for execution agent
            tool_context = ContextFactory.create_tool_context(context, f"execution_{self.execution_agent.name}")
            tool_context.log_tool_usage("execute_with_intelligence", {
                "optimization_status": optimization.get("status"),
                "function_name": original_function.__name__
            })
            
            # Pass context to agent
            result = self.execution_agent.execute_with_intelligence_and_context(
                optimization, tool_context, original_function, *args, **kwargs
            )
            
            # Store execution in context state
            if result.get("status") == "success":
                context.set_state("last_execution", result)
            
            return result
        else:
            # Fallback to original behavior
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