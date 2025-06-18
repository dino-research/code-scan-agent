"""
Intelligent Scanning Module

Module cung cấp intelligent scanning sử dụng Google ADK framework.

Components:
- scanner: Intelligent Code Scanner với ADK agents
- workflows: Sequential workflow agents cho complex tasks
- agents: Google ADK native agents (LlmAgent, SequentialAgent, ParallelAgent)
- context: ADK-compatible context management

Based on: https://google.github.io/adk-docs/
"""

from .scanner import (
    IntelligentCodeScanner,
    intelligent_scan_code_directory,
)

from .workflows import (
    IntelligentWorkflowOrchestrator, 
    apply_intelligent_workflow,
)

# Legacy agents (for backward compatibility)
from .agents import (
    BaseWorkflowAgent,
    AnalysisAgent, 
    OptimizationAgent,
    ExecutionAgent,
    get_agent_class,
    create_adk_compatible_agent
)

# Google ADK native agents
from .agents import (
    create_intelligent_scanning_agent,
    create_sequential_workflow,
    create_parallel_workflow,
    create_single_agent,
    get_supported_models,
    test_adk_agents,
    analyze_project_structure,
    optimize_scan_parameters
)

from .context import (
    WorkflowContext,
    ToolContext,
    BaseContext,
    WorkflowState,
    ArtifactInfo,
    ContextFactory,
    with_context
)

# Legacy compatibility
Agent = BaseWorkflowAgent

__all__ = [
    # Intelligent Scanner
    "IntelligentCodeScanner",
    "intelligent_scan_code_directory",
    
    # Workflow Orchestration
    "IntelligentWorkflowOrchestrator",
    "apply_intelligent_workflow",
    
    # Google ADK Native Agents
    "create_intelligent_scanning_agent",
    "create_sequential_workflow", 
    "create_parallel_workflow",
    "create_single_agent",
    "get_supported_models",
    "test_adk_agents",
    "analyze_project_structure", 
    "optimize_scan_parameters",
    
    # Legacy Agents (backward compatibility)
    "BaseWorkflowAgent",
    "AnalysisAgent",
    "OptimizationAgent", 
    "ExecutionAgent",
    "get_agent_class",
    "create_adk_compatible_agent",
    
    # Context Management
    "WorkflowContext",
    "ToolContext",
    "BaseContext",
    "WorkflowState",
    "ArtifactInfo",
    "ContextFactory",
    "with_context",
    
    # Legacy
    "Agent"
] 