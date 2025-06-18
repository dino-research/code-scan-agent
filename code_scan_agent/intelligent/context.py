"""
ADK-Compatible Context Implementation

Module này implement context objects tương thích với Google ADK patterns
để maintain state, share data, và manage artifacts giữa các workflow steps.

Based on: https://google.github.io/adk-docs/context/
"""

import logging
from typing import Dict, Any, Optional, List
from datetime import datetime
from dataclasses import dataclass, field
import json
import tempfile
import os
from pathlib import Path

logger = logging.getLogger(__name__)

# ============================================================================
# CONTEXT INTERFACES COMPATIBLE WITH ADK
# ============================================================================

@dataclass
class WorkflowState:
    """
    Session state management compatible với ADK patterns
    Stores data that persists across workflow steps
    """
    # Session identification
    session_id: str
    invocation_id: str
    user_id: str = "default"
    
    # Workflow state data
    data: Dict[str, Any] = field(default_factory=dict)
    temporary: Dict[str, Any] = field(default_factory=dict)
    artifacts: Dict[str, str] = field(default_factory=dict)  # key -> file_path
    
    # Metadata
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    last_updated: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get value from state với ADK pattern"""
        return self.data.get(key, default)
    
    def set(self, key: str, value: Any) -> None:
        """Set value in state với ADK pattern"""
        self.data[key] = value
        self.last_updated = datetime.now().isoformat()
    
    def update(self, updates: Dict[str, Any]) -> None:
        """Update multiple values với ADK pattern"""
        self.data.update(updates)
        self.last_updated = datetime.now().isoformat()
    
    def set_temp(self, key: str, value: Any) -> None:
        """Set temporary value (cleared after invocation)"""
        self.temporary[key] = value
    
    def get_temp(self, key: str, default: Any = None) -> Any:
        """Get temporary value"""
        return self.temporary.get(key, default)
    
    def clear_temp(self) -> None:
        """Clear temporary data"""
        self.temporary.clear()


@dataclass 
class ArtifactInfo:
    """Information about an artifact stored in the system"""
    key: str
    file_path: str
    content_type: str
    size: int
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)


class BaseContext:
    """
    Base context class compatible với ADK patterns
    Provides core functionality for state management and artifacts
    """
    
    def __init__(self, state: WorkflowState, temp_dir: Optional[str] = None):
        self.state = state
        self.temp_dir = temp_dir or tempfile.gettempdir()
        self._artifacts_cache: Dict[str, ArtifactInfo] = {}
        logger.debug(f"BaseContext initialized for session {state.session_id}")
    
    # State management methods compatible với ADK
    def get_state(self, key: str, default: Any = None) -> Any:
        """Get state value với ADK pattern"""
        return self.state.get(key, default)
    
    def set_state(self, key: str, value: Any) -> None:
        """Set state value với ADK pattern"""
        self.state.set(key, value)
    
    def update_state(self, updates: Dict[str, Any]) -> None:
        """Update multiple state values với ADK pattern"""
        self.state.update(updates)
    
    # Artifact management methods compatible với ADK
    def save_artifact(self, key: str, content: Any, content_type: str = "application/json") -> str:
        """
        Save artifact và return file path
        Compatible với ADK artifact patterns
        """
        try:
            # Create unique filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{key}_{timestamp}"
            file_path = os.path.join(self.temp_dir, filename)
            
            # Save content based on type
            if content_type == "application/json":
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(content, f, indent=2, ensure_ascii=False)
            elif content_type == "text/plain":
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(str(content))
            else:
                # Binary mode for other types
                with open(file_path, 'wb') as f:
                    if isinstance(content, str):
                        f.write(content.encode('utf-8'))
                    else:
                        f.write(content)
            
            # Store artifact info
            artifact_info = ArtifactInfo(
                key=key,
                file_path=file_path,
                content_type=content_type,
                size=os.path.getsize(file_path),
                metadata={"original_key": key}
            )
            
            self._artifacts_cache[key] = artifact_info
            self.state.artifacts[key] = file_path
            
            logger.debug(f"Artifact saved: {key} -> {file_path}")
            return file_path
            
        except Exception as e:
            logger.error(f"Failed to save artifact {key}: {e}")
            raise ValueError(f"Artifact save failed: {e}")
    
    def load_artifact(self, key: str) -> Any:
        """
        Load artifact content
        Compatible với ADK artifact patterns
        """
        try:
            file_path = self.state.artifacts.get(key)
            if not file_path or not os.path.exists(file_path):
                raise FileNotFoundError(f"Artifact not found: {key}")
            
            artifact_info = self._artifacts_cache.get(key)
            if not artifact_info:
                # Reconstruct artifact info if missing
                artifact_info = ArtifactInfo(
                    key=key,
                    file_path=file_path,
                    content_type="application/json",  # Default
                    size=os.path.getsize(file_path)
                )
            
            # Load content based on type
            if artifact_info.content_type == "application/json":
                with open(file_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            elif artifact_info.content_type == "text/plain":
                with open(file_path, 'r', encoding='utf-8') as f:
                    return f.read()
            else:
                # Binary mode
                with open(file_path, 'rb') as f:
                    return f.read()
                    
        except Exception as e:
            logger.error(f"Failed to load artifact {key}: {e}")
            raise ValueError(f"Artifact load failed: {e}")
    
    def list_artifacts(self) -> List[str]:
        """List available artifact keys"""
        return list(self.state.artifacts.keys())
    
    def get_artifact_info(self, key: str) -> Optional[ArtifactInfo]:
        """Get artifact metadata"""
        return self._artifacts_cache.get(key)


class WorkflowContext(BaseContext):
    """
    Workflow-specific context compatible với ADK InvocationContext patterns
    Provides workflow orchestration capabilities
    """
    
    def __init__(self, state: WorkflowState, workflow_name: str, temp_dir: Optional[str] = None):
        super().__init__(state, temp_dir)
        self.workflow_name = workflow_name
        self.current_step: Optional[str] = None
        self.steps_completed: List[str] = []
        self.workflow_metadata: Dict[str, Any] = {}
        
        # Initialize workflow state
        self.state.set_temp("workflow_name", workflow_name)
        self.state.set_temp("workflow_started_at", datetime.now().isoformat())
        
        logger.info(f"WorkflowContext initialized for workflow: {workflow_name}")
    
    def start_step(self, step_name: str) -> None:
        """Mark start of workflow step"""
        self.current_step = step_name
        self.state.set_temp("current_step", step_name)
        self.state.set_temp(f"step_{step_name}_started_at", datetime.now().isoformat())
        logger.debug(f"Started workflow step: {step_name}")
    
    def complete_step(self, step_name: str, result: Dict[str, Any]) -> None:
        """Mark completion of workflow step với result"""
        if step_name not in self.steps_completed:
            self.steps_completed.append(step_name)
        
        # Store step result
        self.state.set(f"step_{step_name}_result", result)
        self.state.set_temp(f"step_{step_name}_completed_at", datetime.now().isoformat())
        
        # Update workflow metadata
        self.workflow_metadata[f"{step_name}_completed"] = True
        self.workflow_metadata[f"{step_name}_result"] = result.get("status", "unknown")
        
        logger.debug(f"Completed workflow step: {step_name}")
    
    def get_step_result(self, step_name: str) -> Optional[Dict[str, Any]]:
        """Get result from previous workflow step"""
        return self.state.get(f"step_{step_name}_result")
    
    def is_step_completed(self, step_name: str) -> bool:
        """Check if step has been completed"""
        return step_name in self.steps_completed
    
    def get_workflow_summary(self) -> Dict[str, Any]:
        """Get comprehensive workflow summary"""
        return {
            "workflow_name": self.workflow_name,
            "session_id": self.state.session_id,
            "invocation_id": self.state.invocation_id,
            "current_step": self.current_step,
            "steps_completed": self.steps_completed,
            "workflow_metadata": self.workflow_metadata,
            "artifacts_count": len(self.state.artifacts),
            "started_at": self.state.get_temp("workflow_started_at"),
            "duration_ms": self._calculate_duration()
        }
    
    def _calculate_duration(self) -> float:
        """Calculate workflow duration in milliseconds"""
        try:
            started_at = self.state.get_temp("workflow_started_at")
            if started_at:
                start_time = datetime.fromisoformat(started_at)
                duration = datetime.now() - start_time
                return duration.total_seconds() * 1000
        except Exception:
            pass
        return 0.0


class ToolContext(BaseContext):
    """
    Tool-specific context compatible với ADK ToolContext patterns
    Used within individual tools for state and artifact access
    """
    
    def __init__(self, state: WorkflowState, tool_name: str, function_call_id: Optional[str] = None, temp_dir: Optional[str] = None):
        super().__init__(state, temp_dir)
        self.tool_name = tool_name
        self.function_call_id = function_call_id or f"{tool_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        logger.debug(f"ToolContext initialized for tool: {tool_name}")
    
    def log_tool_usage(self, action: str, details: Dict[str, Any] = None) -> None:
        """Log tool usage for debugging và monitoring"""
        log_entry = {
            "tool_name": self.tool_name,
            "function_call_id": self.function_call_id,
            "action": action,
            "timestamp": datetime.now().isoformat(),
            "details": details or {}
        }
        
        # Store in temp state for this invocation
        usage_logs = self.state.get_temp("tool_usage_logs", [])
        usage_logs.append(log_entry)
        self.state.set_temp("tool_usage_logs", usage_logs)
        
        logger.debug(f"Tool usage logged: {self.tool_name}.{action}")
    
    def get_tool_logs(self) -> List[Dict[str, Any]]:
        """Get all tool usage logs for this invocation"""
        return self.state.get_temp("tool_usage_logs", [])


# ============================================================================
# CONTEXT FACTORY & UTILITIES
# ============================================================================

class ContextFactory:
    """Factory for creating ADK-compatible context objects"""
    
    @staticmethod
    def create_workflow_context(session_id: str, invocation_id: str, workflow_name: str, user_id: str = "default") -> WorkflowContext:
        """Create workflow context với proper initialization"""
        state = WorkflowState(
            session_id=session_id,
            invocation_id=invocation_id,
            user_id=user_id
        )
        return WorkflowContext(state, workflow_name)
    
    @staticmethod
    def create_tool_context(workflow_context: WorkflowContext, tool_name: str, function_call_id: Optional[str] = None) -> ToolContext:
        """Create tool context from workflow context"""
        return ToolContext(
            state=workflow_context.state,
            tool_name=tool_name,
            function_call_id=function_call_id,
            temp_dir=workflow_context.temp_dir
        )
    
    @staticmethod
    def generate_session_id() -> str:
        """Generate unique session ID"""
        import uuid
        return f"session_{uuid.uuid4().hex[:12]}"
    
    @staticmethod  
    def generate_invocation_id() -> str:
        """Generate unique invocation ID"""
        import uuid
        return f"inv_{uuid.uuid4().hex[:8]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"


# ============================================================================
# CONTEXT UTILITIES
# ============================================================================

def with_context(workflow_name: str):
    """
    Decorator để automatically provide context cho workflow functions
    Compatible với ADK patterns
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            # Create or reuse context
            context = kwargs.get('context')
            if not context:
                session_id = ContextFactory.generate_session_id()
                invocation_id = ContextFactory.generate_invocation_id()
                context = ContextFactory.create_workflow_context(session_id, invocation_id, workflow_name)
                kwargs['context'] = context
            
            # Execute với context
            try:
                result = func(*args, **kwargs)
                
                # Add context metadata to result
                if isinstance(result, dict):
                    result['context_metadata'] = {
                        'session_id': context.state.session_id,
                        'invocation_id': context.state.invocation_id,
                        'workflow_summary': context.get_workflow_summary()
                    }
                
                return result
            finally:
                # Cleanup temporary data
                context.state.clear_temp()
        
        return wrapper
    return decorator 