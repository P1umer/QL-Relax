"""
Context for Output Validation
"""

import json
import os
from datetime import datetime

# Get the directory of the script for relative paths
SCRIPT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class ValidationContext:
    """
    Context for the output validation step.
    """
    
    def __init__(self, cwe_number=None, current_iteration=1, query_name=None, **kwargs):
        """
        Initialize the validation context.
        
        Args:
            cwe_number: The CWE number being processed
            current_iteration: Current iteration number
            **kwargs: Additional parameters including result counts and files
        """
        # Core parameters
        self.cwe_number = cwe_number
        self.current_iteration = current_iteration
        self.query_name = query_name
        
        # Result counts
        self.current_result_count = kwargs.get('current_result_count', 0)
        self.previous_result_count = kwargs.get('previous_result_count', 0)
        self.initial_result_count = kwargs.get('initial_result_count', 0)
        
        # Result analysis
        self.result_distribution = kwargs.get('result_distribution', {})
        self.analysis_result = {}
        self.validation_conclusion = {}
        
        # File paths
        self.original_ql_file = kwargs.get('original_ql_file', '')
        self.modified_ql_file = kwargs.get('modified_ql_file', '')
        
        # Output directory
        default_output_dir = os.path.join(SCRIPT_DIR, 'qlworkspace', f'CWE-{cwe_number:03d}_{query_name}' if query_name else f'CWE-{cwe_number:03d}')
        self.output_dir = kwargs.get('output_dir', default_output_dir)
        
        # Working directory for agent
        self.working_directory = kwargs.get('working_directory', self.output_dir)
        
        # For LLM interactions
        self.messages = []
        
        # Logging
        self.interactions_log = []
    
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
        return f"ValidationContext(cwe={self.cwe_number}, iteration={self.current_iteration}, current={self.current_result_count}, previous={self.previous_result_count})"
    
    def __repr__(self):
        return self.__str__()
    
    def get(self, key, default=None):
        """Get attribute value with default fallback."""
        # Handle key mapping for compatibility
        if key == 'iteration':
            return self.current_iteration
        return getattr(self, key, default)