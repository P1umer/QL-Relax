"""
Context for QL Query Modification
"""

import json
import os
from datetime import datetime

# Get the directory of the script for relative paths
SCRIPT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class ModificationContext:
    """
    Context for the QL query modification step.
    """
    
    def __init__(self, cwe_number=None, ql_file_path=None, current_iteration=1, query_name=None, **kwargs):
        """
        Initialize the modification context.
        
        Args:
            cwe_number: The CWE number being processed
            ql_file_path: Path to the original QL file
            current_iteration: Current iteration number
            **kwargs: Additional parameters
        """
        # Core parameters
        self.cwe_number = cwe_number
        self.ql_file_path = ql_file_path
        self.current_iteration = current_iteration
        self.query_name = query_name or (os.path.splitext(os.path.basename(ql_file_path))[0] if ql_file_path else None)
        
        # Query content
        self.current_ql_content = None
        self.modified_ql_path = None
        
        # Results from previous iterations
        self.previous_results = kwargs.get('previous_results', {})
        
        # Original QL path (for path resolution in modification_config.py)
        self.original_ql_path = kwargs.get('original_ql_path', ql_file_path)
        
        # Output directory
        default_output_dir = os.path.join(SCRIPT_DIR, 'qlworkspace', f'CWE-{cwe_number:03d}_{query_name}' if query_name else f'CWE-{cwe_number:03d}')
        self.output_dir = kwargs.get('output_dir', default_output_dir)
        
        # Working directory for agent
        self.working_directory = kwargs.get('working_directory', self.output_dir)
        
        # For LLM interactions
        self.messages = []
        
        # Logging
        self.interactions_log = []
        
        # Load the original QL content
        if ql_file_path and os.path.exists(ql_file_path):
            with open(ql_file_path, 'r') as f:
                self.current_ql_content = f.read()
    
    def log_interaction(self, action_type, request, response):
        """Log request and response for tracking."""
        interaction = {
            'timestamp': datetime.now().isoformat(),
            'iteration': self.current_iteration,
            'action': action_type,
            'request': request,
            'response': response
        }
        self.interactions_log.append(interaction)
        
        # Save to main interactions log file
        log_file = os.path.join(self.output_dir, 'interactions_log.json')
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        
        # Load existing log if exists
        existing_log = []
        if os.path.exists(log_file):
            with open(log_file, 'r') as f:
                existing_log = json.load(f)
        
        # Append new interaction
        existing_log.append(interaction)
        
        # Save updated log
        with open(log_file, 'w') as f:
            json.dump(existing_log, f, indent=2)
        
        # Also save to iteration-specific directory
        iteration_dir = os.path.join(self.output_dir, f"iteration_{self.current_iteration}")
        os.makedirs(iteration_dir, exist_ok=True)
        
        # Save this specific interaction
        interaction_file = os.path.join(iteration_dir, f"{action_type}_interaction_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        with open(interaction_file, 'w') as f:
            json.dump(interaction, f, indent=2)
    
    def __str__(self):
        return f"ModificationContext(cwe={self.cwe_number}, iteration={self.current_iteration})"
    
    def __repr__(self):
        return self.__str__()
    
    def get(self, key, default=None):
        """Get attribute value with default fallback."""
        # Handle key mapping for compatibility
        if key == 'iteration':
            return self.current_iteration
        return getattr(self, key, default)