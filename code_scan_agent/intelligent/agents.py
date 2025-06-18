"""
Google ADK-Native Agents for Code Scanning Intelligence

Google ADK framework implementation for intelligent code scanning agents.
Follows Google ADK patterns: https://google.github.io/adk-docs/agents/

Features:
- Native ADK LlmAgent, SequentialAgent, ParallelAgent
- FunctionTool integration
- Multi-LLM support (Gemini, OpenAI, Ollama)
"""
import logging
import json
from typing import Dict, Any, List, Optional, Callable
from pathlib import Path

logger = logging.getLogger(__name__)

# Google ADK components (required)
from google.adk.agents import LlmAgent, SequentialAgent, ParallelAgent, LoopAgent
from google.adk.tools import FunctionTool
from google.adk.sessions import State, Session
from google.genai.types import Schema, Content

logger.info("Google ADK framework loaded")


# ===== FUNCTION TOOLS FOR ADK INTEGRATION =====

def analyze_project_structure(project_path: str) -> Dict[str, Any]:
    """Analyze project structure to determine languages and frameworks"""
    logger.info(f"Analyzing project structure: {project_path}")
    
    try:
        path = Path(project_path)
        if not path.exists():
            return {"error": f"Project path does not exist: {project_path}"}
        
        # Detect languages by file extensions
        languages = set()
        frameworks = set()
        file_count = 0
        
        extensions_to_languages = {
            '.py': 'python',
            '.js': 'javascript', 
            '.ts': 'typescript',
            '.java': 'java',
            '.go': 'go',
            '.php': 'php',
            '.rb': 'ruby',
            '.cpp': 'cpp',
            '.c': 'c',
            '.cs': 'csharp'
        }
        
        for file_path in path.rglob('*'):
            if file_path.is_file():
                file_count += 1
                ext = file_path.suffix.lower()
                if ext in extensions_to_languages:
                    languages.add(extensions_to_languages[ext])
                
                # Framework detection
                filename = file_path.name.lower()
                if filename in ['requirements.txt', 'setup.py', 'pyproject.toml']:
                    frameworks.add('python')
                elif filename in ['package.json', 'yarn.lock']:
                    frameworks.add('nodejs')
                elif filename in ['pom.xml', 'build.gradle']:
                    frameworks.add('java')
                elif filename == 'go.mod':
                    frameworks.add('go')
        
        return {
            "status": "success",
            "languages_detected": list(languages),
            "frameworks_detected": list(frameworks),
            "total_files": file_count,
            "analysis_method": "adk_tool_analysis"
        }
        
            
    except Exception as e:
        logger.error(f"Project structure analysis failed: {e}")
        return {"error": f"Analysis failed: {str(e)}"}


def optimize_scan_parameters(analysis_data: str, priority_level: str = "medium") -> Dict[str, Any]:
    """Optimize scanning parameters based on analysis"""
    logger.info(f"Optimizing scan parameters for priority: {priority_level}")
    
    try:
        if isinstance(analysis_data, str):
            from ..serialization_utils import safe_json_loads
            analysis = safe_json_loads(analysis_data, default={}, context="analysis_data_parsing")
        else:
            analysis = analysis_data
        
        # Rule selection based on detected languages and priority
        languages = analysis.get("languages_detected", [])
        frameworks = analysis.get("frameworks_detected", [])
        
        rules = ["auto"]  # Base rule
        
        # Add language-specific rules
        if "python" in languages:
            rules.extend(["p/python", "p/security-audit"])
        if "javascript" in languages or "typescript" in languages:
            rules.extend(["p/javascript", "p/react"])
        if "java" in languages:
            rules.extend(["p/java", "p/spring"])
        
        # Add security rules based on priority
        if priority_level == "high":
            rules.extend(["p/owasp-top-ten", "p/cwe-top-25"])
        elif priority_level == "medium":
            rules.append("p/owasp-top-ten")
        
        # Scan approach based on priority and project size
        file_count = analysis.get("total_files", 0)
        if priority_level == "high" or file_count < 50:
            scan_approach = "comprehensive"
        elif priority_level == "medium" or file_count < 200:
            scan_approach = "targeted"
        else:
            scan_approach = "quick"
        
        return {
            "status": "success",
            "recommended_rules": list(set(rules)),  # Remove duplicates
            "scan_approach": scan_approach,
            "priority_level": priority_level,
            "optimization_method": "adk_tool_optimization",
            "optimization_reason": f"Optimized for {len(languages)} languages, {file_count} files"
        }
        
    except Exception as e:
        logger.error(f"Parameter optimization failed: {e}")
        return {"error": f"Optimization failed: {str(e)}"}


# ===== ADK AGENT FACTORY FUNCTIONS =====

def create_intelligent_scanning_agent(
    model: str = "gemini-2.0-flash",
    workflow_type: str = "sequential"
) -> Any:
    """
    Factory function to create intelligent scanning agents using Google ADK
    
    Args:
        model: LLM model to use
        workflow_type: Type of workflow (sequential, parallel, single)
        
    Returns:
        Configured ADK agent or workflow
    """
    logger.info(f"Creating ADK agent with model: {model}, workflow: {workflow_type}")
    
    if workflow_type == "sequential":
        return create_sequential_workflow(model)
    elif workflow_type == "parallel":
        return create_parallel_workflow(model)
    elif workflow_type == "single":
        return create_single_agent(model)
    else:
        raise ValueError(f"Unsupported workflow type: {workflow_type}")


def create_sequential_workflow(model: str) -> SequentialAgent:
    """Create Sequential workflow using ADK SequentialAgent"""
    
    # Analysis Agent
    analysis_tool = FunctionTool(analyze_project_structure)
    analysis_agent = LlmAgent(
        model=model,
        name="adk_analysis_agent",
        description="Analyzes code projects using ADK tools",
        instruction="""
You are an ADK-powered code analysis agent.

## Your Task:
1. Use the `analyze_project_structure` tool to analyze the project
2. Determine languages, frameworks, and project complexity
3. Provide structured analysis results

## Tool Usage:
- Call `analyze_project_structure` with the project_path parameter
- Extract key information from the tool results

## Response Format:
Return a JSON object with analysis results including languages, frameworks, file counts, and recommendations.
        """,
        tools=[analysis_tool]
    )
    
    # Optimization Agent  
    optimization_tool = FunctionTool(optimize_scan_parameters)
    optimization_agent = LlmAgent(
        model=model,
        name="adk_optimization_agent",
        description="Optimizes scan parameters using ADK tools",
        instruction="""
You are an ADK-powered scan optimization agent.

## Your Task:
1. Use the `optimize_scan_parameters` tool with analysis results
2. Determine optimal rules and scan approach
3. Provide optimization configuration

## Tool Usage:
- Call `optimize_scan_parameters` with analysis_data and priority_level
- Use the previous agent's output as input

## Response Format:
Return optimized scan configuration with rules, approach, and reasoning.
        """,
        tools=[optimization_tool]
    )
    
    # Create Sequential Workflow
    workflow = SequentialAgent(
        name="adk_intelligent_scanning_workflow",
        description="ADK Sequential workflow for intelligent code scanning",
        sub_agents=[analysis_agent, optimization_agent]
    )
    
    return workflow


def create_parallel_workflow(model: str) -> ParallelAgent:
    """Create Parallel workflow using ADK ParallelAgent"""
    
    # Structure Analysis Agent
    structure_tool = FunctionTool(analyze_project_structure)
    structure_agent = LlmAgent(
        model=model,
        name="adk_structure_agent",
        description="Analyzes project structure in parallel",
        instruction="Analyze project structure focusing on file organization and architecture patterns.",
        tools=[structure_tool]
    )
    
    # Security Analysis Agent  
    security_tool = FunctionTool(analyze_project_structure)
    security_agent = LlmAgent(
        model=model,
        name="adk_security_agent",
        description="Analyzes security context in parallel",
        instruction="Analyze project for security-relevant patterns and risk factors.",
        tools=[security_tool]
    )
    
    # Create Parallel Workflow
    workflow = ParallelAgent(
        name="adk_parallel_analysis_workflow",
        description="ADK Parallel workflow for comprehensive analysis",
        sub_agents=[structure_agent, security_agent]
    )
    
    return workflow


def create_single_agent(model: str) -> LlmAgent:
    """Create single ADK LlmAgent with multiple tools"""
    
    analysis_tool = FunctionTool(analyze_project_structure)
    optimization_tool = FunctionTool(optimize_scan_parameters)
    
    agent = LlmAgent(
        model=model,
        name="adk_comprehensive_agent",
        description="Single ADK agent with analysis and optimization capabilities",
        instruction="""
You are a comprehensive ADK-powered code scanning agent with multiple capabilities.

## Your Tools:
1. `analyze_project_structure` - Analyze project languages and structure
2. `optimize_scan_parameters` - Optimize scanning configuration

## Your Task:
1. First, analyze the project structure using the analysis tool
2. Then, optimize scan parameters based on the analysis
3. Provide comprehensive results combining both phases

## Workflow:
1. Call `analyze_project_structure` with the project path
2. Use the analysis results to call `optimize_scan_parameters`
3. Combine results into a final recommendation

## Response Format:
Provide comprehensive analysis and optimization results in a structured format.
        """,
        tools=[analysis_tool, optimization_tool]
    )
    
    return agent


# ===== UTILITY FUNCTIONS =====

def get_supported_models() -> List[str]:
    """Get list of supported LLM models via litellm integration"""
    # Google models (native ADK support)
    google_models = [
        "gemini-2.0-flash",
        "gemini-1.5-pro", 
        "gemini-1.5-flash"
    ]
    
    # OpenAI models (via litellm)
    openai_models = [
        "gpt-4",
        "gpt-4-turbo", 
        "gpt-3.5-turbo"
    ]
    
    # Local models (via litellm + Ollama)
    local_models = [
        "ollama/llama2",
        "ollama/codellama",
        "ollama/mistral"
    ]
    
    return google_models + openai_models + local_models


def test_adk_agents() -> Dict[str, Any]:
    """Test function to verify ADK agents are working correctly"""
    results = {"tests": {}}
    
    try:
        analysis_result = analyze_project_structure("/home/dino/Documents/dino-research/code-scan-agent/examples")
        results["tests"]["analysis_tool"] = {
            "status": "success" if analysis_result.get("status") == "success" else "failed",
            "languages_found": analysis_result.get("languages_detected", []),
            "files_analyzed": analysis_result.get("total_files", 0)
        }
    except Exception as e:
        results["tests"]["analysis_tool"] = {"status": "error", "error": str(e)}
    
    try:
        from ..serialization_utils import safe_json_dumps
        test_analysis = safe_json_dumps({"languages_detected": ["python"], "total_files": 5}, context="test_analysis")
        optimization_result = optimize_scan_parameters(test_analysis, "medium")
        results["tests"]["optimization_tool"] = {
            "status": "success" if optimization_result.get("status") == "success" else "failed",
            "rules_recommended": optimization_result.get("recommended_rules", [])
        }
    except Exception as e:
        results["tests"]["optimization_tool"] = {"status": "error", "error": str(e)}
    
    # Test agent creation
    
    try:
        sequential_workflow = create_intelligent_scanning_agent("gemini-2.0-flash", "sequential")
        results["tests"]["sequential_workflow"] = {
            "status": "success",
            "type": type(sequential_workflow).__name__,
            "name": getattr(sequential_workflow, 'name', 'unknown')
        }
    except Exception as e:
        results["tests"]["sequential_workflow"] = {"status": "error", "error": str(e)}
    
    try:
        single_agent = create_intelligent_scanning_agent("gemini-2.0-flash", "single")
        results["tests"]["single_agent"] = {
            "status": "success",
            "type": type(single_agent).__name__,
            "name": getattr(single_agent, 'name', 'unknown')
        }
    except Exception as e:
        results["tests"]["single_agent"] = {"status": "error", "error": str(e)}
    
    return results


# ===== LEGACY COMPATIBILITY =====

# For backward compatibility with existing code
class Agent:
    """Legacy compatibility class"""
    def __init__(self, name: str, **kwargs):
        self.name = name
        self.__dict__.update(kwargs)


class BaseWorkflowAgent:
    """Legacy base workflow agent - maintained for backward compatibility"""
    def __init__(self, name: str, description: str = "", **kwargs):
        self.name = name
        self.description = description
        self.__dict__.update(kwargs)


class AnalysisAgent(Agent):
    """Legacy compatibility wrapper for ADK analysis agent"""
    def __init__(self, name: str = "analysis_agent"):
        super().__init__(name)
        self._adk_agent = None
    
    def analyze_context(self, inputs: Dict[str, Any]) -> Dict[str, Any]:
        """Legacy method with ADK agent delegation"""
        if self._adk_agent is None:
            self._adk_agent = create_intelligent_scanning_agent(workflow_type="single")
        
        return {
            "status": "success", 
            "analysis": inputs, 
            "legacy_mode": True
        }


class OptimizationAgent(Agent):
    """Legacy compatibility wrapper for ADK optimization agent"""
    def __init__(self, name: str = "optimization_agent"):
        super().__init__(name)
        self._adk_agent = None
    
    def optimize_approach_with_context(self, analysis: Dict[str, Any], tool_context) -> Dict[str, Any]:
        """Legacy method with ADK agent delegation"""
        if self._adk_agent is None:
            self._adk_agent = create_intelligent_scanning_agent(workflow_type="single")
        
        return {
            "status": "success", 
            "optimization": analysis, 
            "legacy_mode": True
        }


class ExecutionAgent(Agent):
    """Legacy compatibility wrapper for ADK execution agent"""  
    def __init__(self, name: str = "execution_agent"):
        super().__init__(name)
        self._adk_agent = None
    
    def execute_with_intelligence_and_context(self, optimization: Dict[str, Any], tool_context, 
                                           original_function, *args, **kwargs) -> Dict[str, Any]:
        """Legacy method with ADK agent delegation"""
        if self._adk_agent is None:
            self._adk_agent = create_intelligent_scanning_agent(workflow_type="single")
        
        try:
            result = original_function(*args, **kwargs)
            return {
                "status": "success", 
                "result": result, 
                "legacy_mode": True
            }
        except Exception as e:
            return {
                "status": "error", 
                "error": str(e), 
                "legacy_mode": True
            }


# ===== COMPATIBILITY FUNCTIONS =====

def get_agent_class():
    """Return ADK LlmAgent"""
    return LlmAgent


def create_adk_compatible_agent(name: str, description: str = "", model: str = "gemini-2.0-flash", **kwargs):
    """Create an ADK agent with proper configuration"""
    return LlmAgent(
        model=model,
        name=name,
        description=description,
        **kwargs
    ) 