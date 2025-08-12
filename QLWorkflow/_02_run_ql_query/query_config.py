"""
QL Query Execution Configuration
Defines the state machine for running QL queries using CodeQL.
"""

import subprocess
import os
import csv
import json

# Get the directory of the script for relative paths
SCRIPT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def run_ql_query_action(machine):
    """
    Action to execute the QL query using run_juliet.py.
    """
    # Get the QL file path to run
    ql_path = machine.context.ql_file_path
    cwe_number = machine.context.cwe_number
    
    print(f"\n[Run QL Query] Executing query for CWE-{cwe_number} iteration {machine.context.current_iteration}")
    print(f"[Run QL Query] Input QL file: {ql_path}")
    
    # Create output directory for this iteration
    iteration_dir = os.path.join(machine.context.output_dir, f"iteration_{machine.context.current_iteration}")
    os.makedirs(iteration_dir, exist_ok=True)
    
    # Use query_results directory for both input and output
    query_output_dir = os.path.join(iteration_dir, 'query_results')
    os.makedirs(query_output_dir, exist_ok=True)
    
    # The modified query should already be in the passed ql_path
    print(f"[Run QL Query] Using query from: {ql_path}")
    
    # For proper module resolution, we need to run from the project's codeql directory
    # If the query is not already in the codeql directory, copy it there with a different name
    if hasattr(machine.context, 'original_ql_path') and not ql_path.startswith(os.path.dirname(machine.context.original_ql_path)):
        import shutil
        original_dir = os.path.dirname(machine.context.original_ql_path)
        original_name = os.path.basename(machine.context.original_ql_path)
        
        # Create a temporary file with a unique name to avoid conflicts
        temp_name = f"{os.path.splitext(original_name)[0]}_modified_{machine.context.current_iteration}.ql"
        temp_ql_path = os.path.join(original_dir, temp_name)
        
        # Copy the modified QL file to the codeql directory with temp name
        shutil.copy2(ql_path, temp_ql_path)
        print(f"[Run QL Query] Copied modified QL to codeql directory as: {temp_ql_path}")
        
        # Use the temp path in codeql directory for execution
        ql_path = temp_ql_path
        machine.context.temp_ql_path = temp_ql_path  # Store for cleanup later
    else:
        print(f"[Run QL Query] Query already in codeql directory: {ql_path}")
    
    # Construct the command with custom output directory
    command = [
        'python3',
        os.path.join(SCRIPT_DIR, 'run_juliet.py'),
        '--run-queries',
        '--cwe', f'{cwe_number:03d}',
        '--ql', ql_path,
        '--output', query_output_dir
    ]
    
    # Run the command
    try:
        print(f"[Run QL Query] Running command: {' '.join(command)}")
        # record running time
        import time
        start_time = time.time()
        result = subprocess.run(command, capture_output=True, text=True)
        end_time = time.time()
        running_time = end_time - start_time
        print(f"[Run QL Query] Running time: {running_time:.2f} seconds")
        
        # Save command output
        output_log = {
            'command': ' '.join(command),
            'stdout': result.stdout,
            'stderr': result.stderr,
            'returncode': result.returncode,
            'running_time': running_time
        }
        
        # Save log in the query output directory
        log_file = os.path.join(query_output_dir, 'query_execution_log.json')
        with open(log_file, 'w') as f:
            json.dump(output_log, f, indent=2)
        
        if result.returncode != 0:
            return f"Query execution failed: {result.stderr}"
        
        # Look for CSV file in the output directory
        # Both CSV and SARIF files are generated in the same directory
        csv_file = None
        
        # Find CSV file in the output directory
        for file in os.listdir(query_output_dir):
            if file.endswith('.csv'):
                csv_file = os.path.join(query_output_dir, file)
                print(f"[Run QL Query] Found CSV file: {csv_file}")
                break
        
        if not csv_file:
            print(f"[Run QL Query] No CSV file found in {query_output_dir}")
        
        machine.context.query_result_file = csv_file
        
        if not csv_file:
            print(f"[Run QL Query] WARNING: No CSV file found after query execution")
        
        # Clean up temporary file if created
        if hasattr(machine.context, 'temp_ql_path') and os.path.exists(machine.context.temp_ql_path):
            os.remove(machine.context.temp_ql_path)
            print(f"[Run QL Query] Cleaned up temporary QL file: {machine.context.temp_ql_path}")
        
        return "Query executed successfully"
        
    except Exception as e:
        # Clean up temporary file in case of error
        if hasattr(machine.context, 'temp_ql_path') and os.path.exists(machine.context.temp_ql_path):
            os.remove(machine.context.temp_ql_path)
            print(f"[Run QL Query] Cleaned up temporary QL file after error: {machine.context.temp_ql_path}")
        
        return f"Error executing query: {str(e)}"


def parse_query_results_action(machine):
    """
    Parse the SARIF results from the query execution and count threadFlows.
    """
    print(f"[Run QL Query] Parsing query results...")
    print(f"[Run QL Query] CSV file path: {machine.context.query_result_file}")
    
    # Try to find the corresponding SARIF file
    if machine.context.query_result_file:
        # SARIF file should be in the same directory as CSV file
        sarif_path = machine.context.query_result_file.replace('.csv', '.sarif')
    else:
        sarif_path = None
    
    # First try to parse SARIF for threadFlow count
    threadflow_count = 0
    if sarif_path and os.path.exists(sarif_path):
        try:
            with open(sarif_path, 'r', encoding='utf-8') as f:
                sarif_data = json.load(f)
            
            # Count all threadFlows
            for run in sarif_data.get('runs', []):
                for result in run.get('results', []):
                    for code_flow in result.get('codeFlows', []):
                        threadflow_count += len(code_flow.get('threadFlows', []))
            
            print(f"[Run QL Query] Found SARIF file with {threadflow_count} threadFlows")
        except Exception as e:
            print(f"[Run QL Query] Error parsing SARIF: {str(e)}")
    
    # Fall back to CSV parsing if needed
    if not machine.context.query_result_file or not os.path.exists(machine.context.query_result_file):
        machine.context.query_results = []
        machine.context.result_count = threadflow_count if threadflow_count > 0 else 0
        print(f"[Run QL Query] No results file found at: {machine.context.query_result_file}")
        return "No results file found"
    
    try:
        results = []
        with open(machine.context.query_result_file, 'r') as f:
            csv_reader = csv.DictReader(f)
            for row in csv_reader:
                results.append(row)
        
        machine.context.query_results = results
        # Use threadFlow count if available, otherwise use CSV row count
        machine.context.result_count = threadflow_count if threadflow_count > 0 else len(results)
        
        # Calculate result distribution
        from QLWorkflow._02_run_ql_query.query_tools import analyze_result_distribution
        machine.context.result_distribution = analyze_result_distribution(results)
        
        # Determine output directory based on context  
        if machine.context.current_iteration == 1 and hasattr(machine.context, 'is_origin_run') and machine.context.is_origin_run:
            # For origin run in first iteration, save to initial/query_results/
            output_dir = os.path.join(machine.context.output_dir, 'initial', 'query_results')
        else:
            # For all modified queries, save to iteration_X/query_results/
            iteration_dir = os.path.join(machine.context.output_dir, f"iteration_{machine.context.current_iteration}")
            output_dir = os.path.join(iteration_dir, 'query_results')
        
        # Perform evaluation if SARIF exists
        evaluation_metrics = {}
        if sarif_path and os.path.exists(sarif_path):
            from QLWorkflow.util.evaluation_utils import evaluate_sarif_results
            # Pass output_dir to save good/bad results
            # Find the actual CWE directory in Juliet test suite
            testcases_base = os.path.join(SCRIPT_DIR, 'juliet-test-suite-c', 'testcases')
            source_base_dir = None
            if os.path.exists(testcases_base):
                for dirname in os.listdir(testcases_base):
                    if dirname.startswith(f'CWE{machine.context.cwe_number}_'):
                        source_base_dir = os.path.join(testcases_base, dirname)
                        break
            
            evaluation_metrics = evaluate_sarif_results(sarif_path, output_dir, source_base_dir)
            print(f"[Run QL Query] Evaluation: TP={evaluation_metrics['true_positive_count']}, FP={evaluation_metrics['false_positive_count']}")
            print(f"[Run QL Query] Saved good_results.json and bad_results.json to {output_dir}")
        
        # Save complete results with evaluation metrics
        complete_results = {
            'ql_file': machine.context.ql_file_path,
            'result_count': machine.context.result_count,
            'csv_file': machine.context.query_result_file,
            'sarif_file': sarif_path if sarif_path and os.path.exists(sarif_path) else None
        }
        
        # Add evaluation metrics if available
        if evaluation_metrics:
            complete_results.update(evaluation_metrics)
            # Store in context for later use
            machine.context.evaluation_metrics = evaluation_metrics
        
        complete_results_file = os.path.join(output_dir, 'results_log.json')
        with open(complete_results_file, 'w') as f:
            json.dump(complete_results, f, indent=2)
        
        print(f"[Run QL Query] Parsed {machine.context.result_count} results")
        return f"Parsed {machine.context.result_count} results"
        
    except Exception as e:
        machine.context.query_results = []
        machine.context.result_count = 0
        return f"Error parsing results: {str(e)}"


def exit_action(machine):
    """Exit action - cleanup temp files and return the result count."""
    # Clean up temporary QL file if it was created
    if hasattr(machine.context, 'temp_ql_path') and machine.context.temp_ql_path:
        if os.path.exists(machine.context.temp_ql_path):
            try:
                os.remove(machine.context.temp_ql_path)
                print(f"[Run QL Query] Cleaned up temporary file: {machine.context.temp_ql_path}")
            except Exception as e:
                print(f"[Run QL Query] Warning: Failed to clean up temp file: {e}")
    
    return machine.context.result_count


# State machine configuration for query execution
state_definitions = {
    'RunQLQuery': {
        'action': run_ql_query_action,
        'next_state_func': lambda result, machine: 'ParseResults' if 'successfully' in result.lower() else 'Exit',
    },
    'ParseResults': {
        'action': parse_query_results_action,
        'next_state_func': lambda result, machine: 'Exit',
    },
    'Exit': {
        'action': exit_action,
        'next_state_func': None,
    },
}