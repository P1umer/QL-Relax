"""
Context for Iteration Control
"""

import os

# Get the directory of the script for relative paths
SCRIPT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class IterationContext:
    """
    Context for the iteration control workflow.
    """
    
    def __init__(self, cwe_number=None, ql_file_path=None, max_iterations=5, query_name=None, **kwargs):
        """
        Initialize the iteration control context.
        
        Args:
            cwe_number: The CWE number being processed
            ql_file_path: Original QL file path
            max_iterations: Maximum number of iterations
            **kwargs: Additional parameters
        """
        # Core parameters
        self.cwe_number = cwe_number
        self.original_ql_path = ql_file_path
        self.current_ql_path = ql_file_path  # Will be updated each iteration
        self.max_iterations = max_iterations
        self.query_name = query_name or (os.path.splitext(os.path.basename(ql_file_path))[0] if ql_file_path else None)
        
        # Iteration tracking
        self.current_iteration = 1
        self.iteration_history = []
        
        # Result tracking
        self.initial_result_count = kwargs.get('initial_result_count', 0)
        self.previous_result_count = self.initial_result_count
        self.current_result_count = self.initial_result_count
        
        # Validation tracking
        self.last_validation = None
        self.stop_reason = None
        
        # Output directory
        default_output_dir = os.path.join(SCRIPT_DIR, 'qlworkspace', f'CWE-{cwe_number:03d}_{self.query_name}' if self.query_name else f'CWE-{cwe_number:03d}')
        self.output_dir = kwargs.get('output_dir', default_output_dir)
        
        # Final report
        self.final_report = None
        
        # For LLM interactions
        self.messages = []
        
        # Working directory for agent compatibility
        self.working_directory = self.output_dir
    
    def get(self, key, default=None):
        """
        Get attribute value with dictionary-style access for compatibility with agent action utils.
        """
        # Handle key mapping for compatibility
        if key == 'iteration':
            return self.current_iteration
        return getattr(self, key, default)
    
    def __str__(self):
        return f"IterationContext(cwe={self.cwe_number}, iteration={self.current_iteration}/{self.max_iterations})"
    
    def __repr__(self):
        return self.__str__()