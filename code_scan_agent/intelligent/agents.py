"""
ADK Agent Base Classes

Module này cung cấp các base class cho các intelligent agents
để đảm bảo khả năng tương thích với Google ADK framework.

Khi không có ADK, các class này sẽ được sử dụng thay thế.
"""
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

class Agent:
    """
    Custom Agent base class đảm bảo tương thích với google.adk.agents.Agent
    
    Implements minimum interface to be compatible with ADK patterns
    """
    
    def __init__(self, name: str, **kwargs):
        # Accept arbitrary kwargs để tương thích với ADK Agent signature
        self.name = name
        self.config: Dict[str, Any] = kwargs
        self.created_at = self._get_timestamp()
        logger.debug(f"Agent '{name}' initialized with config: {kwargs}")
    
    def _get_timestamp(self) -> str:
        """Get current timestamp"""
        from datetime import datetime
        return datetime.now().isoformat()


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
            # Apply optimizations to parameters
            enhanced_params = optimization.get("enhanced_params", {})
            
            # Filter enhanced params to only include valid function arguments
            import inspect
            try:
                sig = inspect.signature(original_function)
                valid_params = {k: v for k, v in enhanced_params.items() if k in sig.parameters}
                updated_kwargs = {**kwargs, **valid_params}
            except Exception:
                # Fallback if inspection fails
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

# Compatibility function to get ADK Agent if available
def get_agent_class():
    """Return Agent class từ Google ADK hoặc custom implementation"""
    try:
        from google.adk.agents import Agent as ADKAgent
        return ADKAgent
    except ImportError:
        return Agent 