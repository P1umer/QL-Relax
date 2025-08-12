"""
Logging utilities for QLWorkflow
"""

from pathlib import Path
from typing import Dict, Any, Optional


def get_ql_workflow_log_path(context: Dict[str, Any]) -> Optional[Path]:
    """
    Get the log path for QLWorkflow sessions based on CWE and iteration.
    
    Args:
        context: Context containing CWE number, query name, iteration, etc.
        
    Returns:
        Path object for the log directory, or None if insufficient context
    """
    # The output_dir already contains the CWE-XXX_QueryName format
    output_dir = context.get('output_dir')
    if not output_dir:
        return None
    
    base_log_dir = Path(output_dir)
    iteration = context.get('iteration', 1)
    
    # Special handling for initial evaluation (iteration 0)
    if iteration == 0:
        return base_log_dir / 'initial' / 'session_log'
    else:
        return base_log_dir / f"iteration_{iteration}" / 'session_log'


def get_action_type_from_prompt(prompt: str) -> str:
    """
    Determine action type based on prompt content.
    
    Args:
        prompt: The prompt text
        
    Returns:
        Action type string ('modification', 'validation', or 'general')
    """
    prompt_lower = prompt.lower()
    
    if any(keyword in prompt_lower for keyword in ['modifying ql', 'modify', 'modification', 'broaden', 'compile error']):
        return 'modification'
    elif any(keyword in prompt_lower for keyword in ['validation', 'analyze', 'result distribution', 'query results']):
        return 'validation'
    else:
        return 'general'