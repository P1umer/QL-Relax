"""
Tools for QL Query Execution
"""

import os
import subprocess
import json

# Get the directory of the script for relative paths
SCRIPT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def check_database_exists(cwe_number):
    """Check if the CodeQL database exists for the given CWE."""
    db_path = os.path.join(SCRIPT_DIR, 'juliet-test-suite-c', 'testcasesdb', f'CWE{cwe_number}_cpp-db')
    return os.path.exists(db_path)


def create_database_if_needed(cwe_number):
    """Create the CodeQL database if it doesn't exist."""
    if not check_database_exists(cwe_number):
        command = [
            'python3',
            os.path.join(SCRIPT_DIR, 'run_juliet.py'),
            '--create-db',
            '--cwe', f'{cwe_number:03d}'
        ]
        
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode != 0:
            return False, f"Failed to create database: {result.stderr}"
        
        return True, "Database created successfully"
    
    return True, "Database already exists"


def get_query_metadata(ql_file_path):
    """Extract metadata from the QL file."""
    metadata = {
        'filename': os.path.basename(ql_file_path),
        'directory': os.path.dirname(ql_file_path),
        'size': os.path.getsize(ql_file_path) if os.path.exists(ql_file_path) else 0
    }
    
    if os.path.exists(ql_file_path):
        with open(ql_file_path, 'r') as f:
            content = f.read()
            # Count lines
            metadata['lines'] = len(content.split('\n'))
            # Check for specific patterns
            metadata['has_dataflow'] = 'DataFlow' in content or 'TaintTracking' in content
            metadata['has_guards'] = 'isBarrier' in content or 'isSanitizer' in content
    
    return metadata


def analyze_result_distribution(results):
    """Analyze the distribution of query results."""
    distribution = {}
    
    for result in results:
        # Group by file or location
        if 'File' in result:
            file_path = result['File']
            file_name = os.path.basename(file_path)
            distribution[file_name] = distribution.get(file_name, 0) + 1
    
    return distribution