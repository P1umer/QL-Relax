"""
Tools for QL Query Modification
"""

import os
import re


def extract_ql_metadata(ql_content):
    """Extract metadata from QL query content."""
    metadata = {
        'tags': [],
        'kind': None,
        'description': None,
        'cwe_numbers': []
    }
    
    # Extract @tags
    tag_matches = re.findall(r'\* @tags?\s+(.+)', ql_content)
    for match in tag_matches:
        tags = [tag.strip() for tag in match.split()]
        metadata['tags'].extend(tags)
    
    # Extract @kind
    kind_match = re.search(r'\* @kind\s+(.+)', ql_content)
    if kind_match:
        metadata['kind'] = kind_match.group(1).strip()
    
    # Extract @description
    desc_match = re.search(r'\* @description\s+(.+)', ql_content)
    if desc_match:
        metadata['description'] = desc_match.group(1).strip()
    
    # Extract CWE numbers from tags
    for tag in metadata['tags']:
        cwe_match = re.match(r'external/cwe/cwe-(\d+)', tag, re.IGNORECASE)
        if cwe_match:
            metadata['cwe_numbers'].append(int(cwe_match.group(1)))
    
    return metadata


def validate_ql_syntax(ql_content):
    """Basic validation of QL syntax (placeholder for actual validation)."""
    # Check for basic QL structure
    required_patterns = [
        r'import\s+\w+',  # Import statements
        r'from\s+.+\s+where\s+.+\s+select',  # Basic query structure
    ]
    
    for pattern in required_patterns:
        if not re.search(pattern, ql_content, re.IGNORECASE | re.DOTALL):
            return False, f"Missing required pattern: {pattern}"
    
    return True, "Basic syntax validation passed"


def compare_query_versions(original_content, modified_content):
    """Compare original and modified queries to identify changes."""
    changes = {
        'lines_added': 0,
        'lines_removed': 0,
        'structural_changes': []
    }
    
    original_lines = original_content.split('\n')
    modified_lines = modified_content.split('\n')
    
    # Simple line count comparison
    changes['lines_added'] = max(0, len(modified_lines) - len(original_lines))
    changes['lines_removed'] = max(0, len(original_lines) - len(modified_lines))
    
    # Check for structural changes (simplified)
    original_imports = len(re.findall(r'^import\s+', original_content, re.MULTILINE))
    modified_imports = len(re.findall(r'^import\s+', modified_content, re.MULTILINE))
    
    if modified_imports > original_imports:
        changes['structural_changes'].append('Added new imports')
    
    # Check for predicate additions
    original_predicates = len(re.findall(r'^predicate\s+\w+', original_content, re.MULTILINE))
    modified_predicates = len(re.findall(r'^predicate\s+\w+', modified_content, re.MULTILINE))
    
    if modified_predicates > original_predicates:
        changes['structural_changes'].append('Added new predicates')
    
    return changes