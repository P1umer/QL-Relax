"""
Enhanced evaluation utilities using CodeQL-extracted function boundaries.
"""

import json
import os
import csv
import subprocess
import time

# Get the directory of the script for relative paths
SCRIPT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def extract_functions_for_cwe(cwe_number):
    """
    Extract function boundaries for a specific CWE using CodeQL.
    Returns a dictionary mapping (file_path, line_number) to function info.
    """
    # Paths
    query_file = os.path.join(SCRIPT_DIR, 'QLWorkflow', 'util', 'function_dump.ql')
    util_dir = os.path.join(SCRIPT_DIR, 'qlworkspace', 'util')
    os.makedirs(util_dir, exist_ok=True)
    output_csv = os.path.join(util_dir, f'cwe{cwe_number}_functions.csv')
    
    # Check if cached CSV exists and is recent (within 1 hour)
    if os.path.exists(output_csv):
        file_age = time.time() - os.path.getmtime(output_csv)
        if file_age < 3600:  # 1 hour cache
            print(f"Using cached function boundaries from {output_csv}")
            # Parse and return cached data
            function_map = {}
            with open(output_csv, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    func_name = row['col0']
                    file_path = row['col1']
                    start_line = int(row['col2'])
                    end_line = int(row['col3'])
                    
                    # Normalize file path - remove /workspace prefix
                    if file_path.startswith('/workspace/'):
                        file_path = file_path[11:]
                    
                    # Store function info for all lines in its range
                    for line_num in range(start_line, end_line + 1):
                        key = (file_path, line_num)
                        function_map[key] = {
                            'name': func_name,
                            'start_line': start_line,
                            'end_line': end_line,
                            'type': classify_function_name(func_name)
                        }
            return function_map
    
    # Run query using run_juliet.py
    command = [
        'python3',
        os.path.join(SCRIPT_DIR, 'run_juliet.py'),
        '--run-queries',
        '--cwe', f'{cwe_number:03d}',
        '--ql', query_file,
        '--output', util_dir
    ]
    
    print(f"Extracting function boundaries for CWE-{cwe_number}...")
    result = subprocess.run(command, capture_output=True, text=True)
    
    if result.returncode != 0:
        print(f"Error running query: {result.stderr}")
        return {}
    
    # The output file should be named based on the query file
    # run_juliet.py outputs files as {cwe_name}_{ql_name}.csv
    # We need to find the correct one for this CWE
    expected_output = None
    
    # Look for CSV files that match our CWE number and contain 'function_dump'
    for file in os.listdir(util_dir):
        if file.endswith('.csv') and 'function_dump' in file:
            # Check if this file contains data for our CWE
            file_path = os.path.join(util_dir, file)
            with open(file_path, 'r') as f:
                # Read first few lines to check CWE number
                for _ in range(10):
                    line = f.readline()
                    if f'CWE{cwe_number}_' in line or f'CWE{cwe_number:03d}_' in line:
                        expected_output = file_path
                        break
            if expected_output:
                break
    
    # If still not found, try the most recent function_dump CSV
    if not expected_output:
        csv_files = [f for f in os.listdir(util_dir) if f.endswith('.csv') and 'function_dump' in f]
        if csv_files:
            # Get the most recently modified one
            csv_files_with_time = [(f, os.path.getmtime(os.path.join(util_dir, f))) for f in csv_files]
            csv_files_with_time.sort(key=lambda x: x[1], reverse=True)
            expected_output = os.path.join(util_dir, csv_files_with_time[0][0])
    
    if expected_output and os.path.exists(expected_output) and expected_output != output_csv:
        # Move to our expected location
        os.rename(expected_output, output_csv)
    
    # Parse CSV and build lookup structure
    function_map = {}
    
    # Check if the output CSV exists before trying to open it
    if not os.path.exists(output_csv):
        print(f"Warning: Function boundary CSV not found at {output_csv}")
        return {}
    
    with open(output_csv, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            func_name = row['col0']
            file_path = row['col1']
            start_line = int(row['col2'])
            end_line = int(row['col3'])
            
            # Normalize file path - remove /workspace prefix
            if file_path.startswith('/workspace/'):
                file_path = file_path[11:]  # Remove '/workspace/'
            
            # Store function info for all lines in its range
            for line_num in range(start_line, end_line + 1):
                key = (file_path, line_num)
                function_map[key] = {
                    'name': func_name,
                    'start_line': start_line,
                    'end_line': end_line,
                    'type': classify_function_name(func_name)
                }
    
    # Keep the CSV file for debugging/caching purposes
    # if os.path.exists(output_csv):
    #     os.remove(output_csv)
    
    return function_map


def classify_function_name(func_name):
    """
    Classify function based on its name following Juliet conventions.
    """
    if not func_name:
        return 'unknown'
    
    # Pattern matches
    func_lower = func_name.lower()
    
    # Bad function patterns
    if 'bad' in func_lower:
        return 'bad'
    
    # Good function patterns
    if 'good' in func_lower:
        return 'good'

    return 'unknown'


def get_function_from_line(file_path, line_number, function_map):
    """
    Get function type for a specific line using pre-extracted function data.
    
    Args:
        file_path: Path to the source file
        line_number: Line number to check
        function_map: Pre-extracted function boundaries from CodeQL
        
    Returns:
        str: 'bad', 'good', or 'unknown'
    """
    # Try multiple path variations to find a match
    path_variations = []
    
    # Original path
    path_variations.append(file_path)
    
    # If it's a short path, try to expand it
    if not file_path.startswith('/') and not file_path.startswith('juliet-test-suite-c'):
        # Get CWE number from filename
        import re
        cwe_match = re.search(r'CWE(\d+)_', file_path)
        
        if cwe_match:
            cwe_num = cwe_match.group(1).lstrip('0')
            
            # Check if the file has a subdirectory prefix like s01/
            if file_path.startswith('s'):
                # Look for entries in function_map that contain our file path
                for key in function_map:
                    key_path = key[0]
                    # Check if this key contains our filename
                    if file_path in key_path and f'CWE{cwe_num}_' in key_path:
                        # Extract the CWE directory name
                        if '/testcases/' in key_path:
                            # Find where testcases/ ends and extract the full path after it
                            idx = key_path.find('/testcases/') + len('/testcases/')
                            relative_path = key_path[idx:]
                            path_variations.append(relative_path)
                        
                        # Also try the full path from function map
                        path_variations.append(key_path)
                        
                        # If the key path starts with /workspace/, also try without it
                        if key_path.startswith('/workspace/'):
                            path_variations.append(key_path[11:])  # Remove '/workspace/'
            else:
                # File without subdirectory (like CWE476 files)
                # Look for matching files in function_map
                filename = os.path.basename(file_path)
                for key in function_map:
                    key_path = key[0]
                    if filename in key_path and f'CWE{cwe_num}_' in key_path:
                        # Extract various path patterns
                        if '/testcases/' in key_path:
                            idx = key_path.find('/testcases/') + len('/testcases/')
                            relative_path = key_path[idx:]
                            path_variations.append(relative_path)
                        
                        path_variations.append(key_path)
                        
                        if key_path.startswith('/workspace/'):
                            path_variations.append(key_path[11:])
            
            # Standard patterns - try to find the CWE directory dynamically
            # Look for any directory starting with CWE{num}_
            for key in function_map:
                if f'/CWE{cwe_num}_' in key[0]:
                    # Extract the CWE directory name
                    path_parts = key[0].split('/')
                    for i, part in enumerate(path_parts):
                        if part.startswith(f'CWE{cwe_num}_'):
                            cwe_dir = part
                            if file_path.startswith('s'):
                                # With subdirectory
                                path_variations.append(f'juliet-test-suite-c/testcases/{cwe_dir}/{file_path}')
                                path_variations.append(f'testcases/{cwe_dir}/{file_path}')
                                path_variations.append(f'{cwe_dir}/{file_path}')
                            else:
                                # Without subdirectory
                                path_variations.append(f'juliet-test-suite-c/testcases/{cwe_dir}/{file_path}')
                                path_variations.append(f'testcases/{cwe_dir}/{file_path}')
                                path_variations.append(f'{cwe_dir}/{file_path}')
                            break
                    break
    
    # Try to find in function map
    for normalized_path in path_variations:
        key = (normalized_path, line_number)
        if key in function_map:
            func_info = function_map[key]
            func_type = func_info['type']
            if func_type in ['bad', 'good']:
                return func_type
    
    # If function map is empty or doesn't contain the file, use filename-based classification
    # This is important for cases where function boundaries weren't extracted properly
    if len(function_map) == 0 or not any(file_path in key[0] for key in function_map):
        # Read the file and check function name at the line
        try:
            # Try to find the file
            possible_paths = [
                file_path,
                os.path.join('/hdd2/QL-Relax/juliet-test-suite-c/testcases', file_path)
            ]
            
            # Add CWE-specific paths
            import re
            cwe_match = re.search(r'CWE(\d+)_', file_path)
            if cwe_match:
                # Find CWE directory
                import glob
                cwe_num = cwe_match.group(1).lstrip('0')
                cwe_dirs = glob.glob(f'/hdd2/QL-Relax/juliet-test-suite-c/testcases/CWE{cwe_num}_*')
                for cwe_dir in cwe_dirs:
                    possible_paths.append(os.path.join(cwe_dir, os.path.basename(file_path)))
            
            # Try to read the file
            file_content = None
            for path in possible_paths:
                if os.path.exists(path):
                    with open(path, 'r') as f:
                        file_content = f.readlines()
                    break
            
            if file_content and line_number <= len(file_content):
                # Look backwards from the line to find the function declaration
                for i in range(line_number - 1, -1, -1):
                    line = file_content[i]
                    # Check for function declarations
                    if ('void ' in line or 'int ' in line or 'char ' in line) and '(' in line and '{' in file_content[i:i+3]:
                        # Extract function name
                        import re
                        func_match = re.search(r'(\w+)\s*\(', line)
                        if func_match:
                            func_name = func_match.group(1)
                            return classify_function_name(func_name)
        except:
            pass
    
    # Final fallback to file name patterns if function not found
    if '_bad' in file_path or 'bad_' in file_path:
        return 'bad'
    elif '_good' in file_path or 'good_' in file_path:
        return 'good'
    
    return 'unknown'


def classify_result(thread_flow, sarif_result, function_map):
    """
    Enhanced classification using CodeQL-extracted function boundaries.
    """
    # Check both thread flow locations and result locations
    all_locations = []
    
    # Add thread flow locations
    thread_locations = thread_flow.get('locations', [])
    for location in thread_locations:
        loc = location.get('location', {})
        all_locations.append(loc)
    
    # Add result locations
    result_locations = sarif_result.get('locations', [])
    all_locations.extend(result_locations)
    
    # Check each location using function map
    for loc in all_locations:
        phys_loc = loc.get('physicalLocation', {})
        file_uri = phys_loc.get('artifactLocation', {}).get('uri', '')
        line_num = phys_loc.get('region', {}).get('startLine', 0)
        
        if file_uri and line_num > 0:
            # get_function_from_line already handles file name patterns as fallback
            func_type = get_function_from_line(file_uri, line_num, function_map)
            if func_type != 'unknown':
                return func_type
    
    return 'unknown'


def evaluate_sarif_results(sarif_path, output_dir=None, source_base_dir=None):
    """
    Enhanced evaluation using CodeQL-extracted function boundaries.
    
    Args:
        sarif_path: Path to the SARIF file
        output_dir: Optional directory to save good_results.json and bad_results.json  
        cwe_number: CWE number for extracting function boundaries
        
    Returns:
        dict: Evaluation metrics including TP/FP counts and rates
    """
    if not os.path.exists(sarif_path):
        return {
            'good_result_count': 0,
            'bad_result_count': 0,
            'unknown_result_count': 0,
            'true_positive_count': 0,
            'false_positive_count': 0,
            'true_positive_rate': 0.0,
            'false_positive_rate': 0.0,
            'total_threadflows': 0
        }
    
    # Extract CWE number from path or source_base_dir
    cwe_number = None
    import re
    
    # Try from sarif path first
    cwe_match = re.search(r'CWE-?(\d+)', sarif_path)
    if cwe_match:
        cwe_number = int(cwe_match.group(1).lstrip('0'))
    
    # Try from source_base_dir if not found
    if not cwe_number and source_base_dir:
        cwe_match = re.search(r'CWE(\d+)_', source_base_dir)
        if cwe_match:
            cwe_number = int(cwe_match.group(1).lstrip('0'))
    
    if not cwe_number:
        print("Warning: Could not determine CWE number, using text-based function detection")
        function_map = {}
    else:
        print(f"Extracting function boundaries for CWE-{cwe_number}...")
        function_map = extract_functions_for_cwe(cwe_number)
        print(f"Extracted {len(function_map)} function-line mappings")
    
    try:
        with open(sarif_path, 'r', encoding='utf-8') as f:
            sarif_data = json.load(f)
        
        good_count = 0
        bad_count = 0
        unknown_count = 0
        total_threadflows = 0
        good_results = []
        bad_results = []
        unknown_results = []
        
        for run in sarif_data.get('runs', []):
            for result in run.get('results', []):
                # Get result location info
                result_loc = result.get('locations', [{}])[0].get('physicalLocation', {})
                result_file = result_loc.get('artifactLocation', {}).get('uri', '')
                result_line = result_loc.get('region', {}).get('startLine', 0)
                result_message = result.get('message', {}).get('text', '')
                
                # Check if this is a path-problem query (has codeFlows)
                code_flows = result.get('codeFlows', [])
                if code_flows:
                    # Handle path-problem queries
                    for code_flow in code_flows:
                        for thread_flow in code_flow.get('threadFlows', []):
                            total_threadflows += 1
                        
                        # Create a summary of this threadFlow
                        thread_flow_summary = {
                            'result_location': {
                                'file': result_file,
                                'line': result_line,
                                'message': result_message[:200]  # Truncate long messages
                            },
                            'thread_flow_locations': []
                        }
                        
                        # Add key locations from the threadFlow
                        locations = thread_flow.get('locations', [])
                        for i, location in enumerate(locations):
                            if i == 0 or i == len(locations) - 1:  # First and last locations
                                loc = location.get('location', {})
                                phys_loc = loc.get('physicalLocation', {})
                                thread_flow_summary['thread_flow_locations'].append({
                                    'step': 'source' if i == 0 else 'sink',
                                    'file': phys_loc.get('artifactLocation', {}).get('uri', ''),
                                    'line': phys_loc.get('region', {}).get('startLine', 0),
                                    'message': loc.get('message', {}).get('text', '')[:100]
                                })
                        
                        classification = classify_result(thread_flow, result, function_map)
                        if classification == 'bad':
                            bad_count += 1
                            bad_results.append(thread_flow_summary)
                        elif classification == 'good':
                            good_count += 1
                            good_results.append(thread_flow_summary)
                        else:  # unknown
                            unknown_count += 1
                            unknown_results.append(thread_flow_summary)
                else:
                    # Handle regular problem queries (no codeFlows)
                    total_threadflows += 1
                    
                    # Create a summary for this result
                    result_summary = {
                        'result_location': {
                            'file': result_file,
                            'line': result_line,
                            'message': result_message[:200]  # Truncate long messages
                        }
                    }
                    
                    # Classify based on result location instead of threadFlow
                    classification = get_function_from_line(result_file, result_line, function_map)
                    if classification == 'bad':
                        bad_count += 1
                        bad_results.append(result_summary)
                    elif classification == 'good':
                        good_count += 1
                        good_results.append(result_summary)
                    else:  # unknown
                        unknown_count += 1
                        unknown_results.append(result_summary)
        
        # In Juliet test suite:
        # - True Positive (TP): Finding a vulnerability in a "bad" function
        # - False Positive (FP): Finding a vulnerability in a "good" function or unmarked function
        true_positive_count = bad_count
        false_positive_count = good_count + unknown_count
        
        # Calculate rates based on all results
        total = true_positive_count + false_positive_count
        true_positive_rate = (true_positive_count / total * 100) if total > 0 else 0.0
        false_positive_rate = (false_positive_count / total * 100) if total > 0 else 0.0
        
        # Save results by category if output directory is provided
        if output_dir and os.path.exists(output_dir):
            # Save good results (false positives)
            good_results_file = os.path.join(output_dir, 'good_results.json')
            with open(good_results_file, 'w', encoding='utf-8') as f:
                json.dump({
                    'count': good_count,
                    'description': 'ThreadFlows in code marked as "good" (known false positives)',
                    'results': good_results
                }, f, indent=2)
            
            # Save bad results (true positives)
            bad_results_file = os.path.join(output_dir, 'bad_results.json')
            with open(bad_results_file, 'w', encoding='utf-8') as f:
                json.dump({
                    'count': bad_count,
                    'description': 'ThreadFlows in code marked as "bad" (true positives)',
                    'results': bad_results
                }, f, indent=2)
            
            # Save unknown results
            unknown_results_file = os.path.join(output_dir, 'unknown_results.json')
            with open(unknown_results_file, 'w', encoding='utf-8') as f:
                json.dump({
                    'count': unknown_count,
                    'description': 'ThreadFlows in unmarked code (classification unknown)',
                    'results': unknown_results
                }, f, indent=2)
        
        return {
            'good_result_count': good_count,
            'bad_result_count': bad_count,
            'unknown_result_count': unknown_count,
            'true_positive_count': true_positive_count,
            'false_positive_count': false_positive_count,
            'true_positive_rate': round(true_positive_rate, 2),
            'false_positive_rate': round(false_positive_rate, 2),
            'total_threadflows': total_threadflows
        }
        
    except Exception as e:
        print(f"[Evaluation] Error evaluating SARIF: {str(e)}")
        import traceback
        traceback.print_exc()
        return {
            'good_result_count': 0,
            'bad_result_count': 0,
            'unknown_result_count': 0,
            'true_positive_count': 0,
            'false_positive_count': 0,
            'true_positive_rate': 0.0,
            'false_positive_rate': 0.0,
            'total_threadflows': 0,
            'error': str(e)
        }

