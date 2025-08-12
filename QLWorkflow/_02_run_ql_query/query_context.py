"""
Context for QL Query Execution
"""

import os

# Get the directory of the script for relative paths
SCRIPT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class QueryContext:
    """
    Context for the QL query execution step.
    """
    
    def __init__(self, cwe_number=None, ql_file_path=None, current_iteration=1, query_name=None, **kwargs):
        """
        Initialize the query execution context.
        
        Args:
            cwe_number: The CWE number being processed
            ql_file_path: Path to the QL file to execute
            current_iteration: Current iteration number
            query_name: Name of the query
            **kwargs: Additional parameters
        """
        # Core parameters
        self.cwe_number = cwe_number
        self.ql_file_path = ql_file_path
        self.current_iteration = current_iteration
        self.query_name = query_name or (os.path.basename(ql_file_path).split('.')[0] if ql_file_path else None)
        
        # Query execution results
        self.query_result_file = None
        self.query_results = []
        self.result_count = 0
        self.result_distribution = {}
        
        # Output directory
        default_output_dir = os.path.join(SCRIPT_DIR, 'qlworkspace', f'CWE-{cwe_number:03d}_{self.query_name}' if self.query_name else f'CWE-{cwe_number:03d}')
        self.output_dir = kwargs.get('output_dir', default_output_dir)
        
        # For LLM interactions (if needed)
        self.messages = []
        
        # Previous iteration data
        self.previous_result_count = kwargs.get('previous_result_count', 0)
        
        # Store original QL path for module resolution
        self.original_ql_path = kwargs.get('original_ql_path', None)
        
        # Working directory for agent compatibility
        self.working_directory = kwargs.get('working_directory', self.output_dir)
    
    def get(self, key, default=None):
        """
        Get attribute value with dictionary-style access for compatibility with agent action utils.
        """
        # Handle key mapping for compatibility
        if key == 'iteration':
            return self.current_iteration
        return getattr(self, key, default)
    
    def __str__(self):
        return f"QueryContext(cwe={self.cwe_number}, iteration={self.current_iteration})"
    
    def __repr__(self):
        return self.__str__()