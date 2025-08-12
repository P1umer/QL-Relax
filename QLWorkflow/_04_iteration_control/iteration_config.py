"""
Iteration Control Configuration
Manages the iteration loop for the QL workflow pipeline.
"""

from BaseMachine.action_utils import call_sub_state_machine_action
import json
import os
from datetime import datetime

# Get the directory of the script for relative paths
SCRIPT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import sub-workflow configurations
from QLWorkflow._01_ql_query_modification.modification_config import state_definitions as modification_states
from QLWorkflow._02_run_ql_query.query_config import state_definitions as query_states
from QLWorkflow._03_output_validation.validation_config import state_definitions as validation_states
# Removed evaluation imports

# Import contexts
from QLWorkflow._01_ql_query_modification.modification_context import ModificationContext
from QLWorkflow._02_run_ql_query.query_context import QueryContext
from QLWorkflow._03_output_validation.validation_context import ValidationContext
# Removed evaluation context import


def check_iteration_limit_action(machine):
    """
    Check if we've reached the maximum iteration limit.
    """
    current_iteration = machine.context.current_iteration
    max_iterations = machine.context.max_iterations
    
    print(f"\n[Iteration Control] Checking iteration {current_iteration}/{max_iterations} for CWE-{machine.context.cwe_number}")
    
    # Save iteration control status
    iteration_dir = os.path.join(machine.context.output_dir, f"iteration_{machine.context.current_iteration}")
    os.makedirs(iteration_dir, exist_ok=True)

    if current_iteration > max_iterations:
        machine.context.stop_reason = f"Reached maximum iterations ({max_iterations})"
        print(f"[Iteration Control] Maximum iterations reached")
        return "max_reached"
    
    print(f"[Iteration Control] Continuing with iteration {current_iteration}")
    return "continue"


def save_origin_query_action(machine):
    """
    Save and run the original/previous query.
    For iteration 1: save to initial/query_results/ directory
    For iteration N: use results from iteration_(N-1)/query_results/
    """
    if machine.context.current_iteration == 1:
        # First iteration: create initial/query_results directory and run original query
        query_origin_dir = os.path.join(machine.context.output_dir, "initial", "query_results")
        os.makedirs(query_origin_dir, exist_ok=True)
    else:
        # Later iterations: use previous iteration's results
        prev_iteration = machine.context.current_iteration - 1
        query_origin_dir = os.path.join(machine.context.output_dir, f"iteration_{prev_iteration}", "query_results")
        
        # Check if previous iteration results exist
        if not os.path.exists(query_origin_dir):
            raise FileNotFoundError(f"Previous iteration results not found: {query_origin_dir}")
        
        # No need to run query again, just set the origin directory and return
        machine.context.query_origin_dir = query_origin_dir
        
        # Load previous results for comparison
        ql_filename = os.path.basename(machine.context.original_ql_path)
        ql_name = os.path.splitext(ql_filename)[0]
        csv_file = os.path.join(query_origin_dir, f"CWE-{machine.context.cwe_number:03d}_{ql_name}.csv")
        # SARIF file should be in the same directory as CSV
        sarif_file = csv_file.replace('.csv', '.sarif')
        
        # Count threadFlows from SARIF if available
        threadflow_count = 0
        if os.path.exists(sarif_file):
            try:
                with open(sarif_file, 'r', encoding='utf-8') as f:
                    sarif_data = json.load(f)
                
                for run in sarif_data.get('runs', []):
                    for result in run.get('results', []):
                        for code_flow in result.get('codeFlows', []):
                            threadflow_count += len(code_flow.get('threadFlows', []))
                
                machine.context.original_result_count = threadflow_count
                machine.context.previous_result_count = threadflow_count
                
                # Perform evaluation on previous iteration SARIF
                from QLWorkflow.util.evaluation_utils import evaluate_sarif_results
                # Note: Don't save good/bad results here as they already exist in the previous iteration
                # Find the actual CWE directory in Juliet test suite
                testcases_base = 'juliet-test-suite-c/testcases'
                source_base_dir = None
                if os.path.exists(testcases_base):
                    for dirname in os.listdir(testcases_base):
                        if dirname.startswith(f'CWE{machine.context.cwe_number}_'):
                            source_base_dir = os.path.join(testcases_base, dirname)
                            break
                
                evaluation_metrics = evaluate_sarif_results(sarif_file, source_base_dir=source_base_dir)
                if evaluation_metrics:
                    machine.context.previous_evaluation_metrics = evaluation_metrics
                    print(f"[Iteration Control] Previous iteration: {threadflow_count} threadFlows, TP={evaluation_metrics['true_positive_count']}, FP={evaluation_metrics['false_positive_count']}")
                else:
                    print(f"[Iteration Control] Using previous iteration results: {threadflow_count} threadFlows from SARIF")
            except Exception as e:
                print(f"[Iteration Control] Error reading SARIF: {e}")
                # Fall back to CSV
                if os.path.exists(csv_file):
                    results = []
                    import csv
                    with open(csv_file, 'r') as f:
                        csv_reader = csv.DictReader(f)
                        for row in csv_reader:
                            results.append(row)
                    machine.context.original_result_count = len(results)
                    machine.context.previous_result_count = len(results)
                    print(f"[Iteration Control] Fallback to CSV: {len(results)} results")
                else:
                    machine.context.original_result_count = 0
                    machine.context.previous_result_count = 0
        elif os.path.exists(csv_file):
            # Fall back to CSV if no SARIF
            results = []
            import csv
            with open(csv_file, 'r') as f:
                csv_reader = csv.DictReader(f)
                for row in csv_reader:
                    results.append(row)
            machine.context.original_result_count = len(results)
            machine.context.previous_result_count = len(results)
            print(f"[Iteration Control] Using CSV results: {len(results)} results")
        else:
            machine.context.original_result_count = 0
            machine.context.previous_result_count = 0
            
        return "Using previous iteration results"
    
    # For first iteration: run the original query and save to initial/
    import shutil
    
    # Use the original QL file for first iteration
    source_ql_path = machine.context.original_ql_path
    print(f"[Iteration Control] Using original QL file: {source_ql_path}")
    
    # Copy the original QL file to initial directory
    original_ql_filename = os.path.basename(machine.context.original_ql_path)
    origin_ql_copy = os.path.join(query_origin_dir, original_ql_filename)
    shutil.copy2(source_ql_path, origin_ql_copy)
    
    # Save metadata about the origin
    origin_metadata = {
        'iteration': machine.context.current_iteration,
        'source_type': 'original',
        'source_path': source_ql_path,
        'description': f'Origin query for iteration {machine.context.current_iteration}'
    }
    metadata_file = os.path.join(query_origin_dir, 'origin_metadata.json')
    with open(metadata_file, 'w') as f:
        json.dump(origin_metadata, f, indent=2)
    
    # Run the original query to get baseline results
    print(f"\n[Iteration Control] Running original query for comparison (iteration {machine.context.current_iteration})")
    
    # Create a special query context that outputs to initial/ directory
    origin_context = QueryContext(
        cwe_number=machine.context.cwe_number,
        ql_file_path=source_ql_path,  # Use the determined source path
        current_iteration=machine.context.current_iteration,
        previous_result_count=0,
        output_dir=machine.context.output_dir,
        original_ql_path=machine.context.original_ql_path
    )
    # Set flag to indicate this is the origin run
    origin_context.is_origin_run = True
    
    # Run query execution, but save results to query_results_origin
    # We need to temporarily override the output directory logic
    import subprocess
    
    command = [
        'python3',
        os.path.join(SCRIPT_DIR, 'run_juliet.py'),
        '--run-queries',
        '--cwe', f'{machine.context.cwe_number:03d}',
        '--ql', source_ql_path,  # Use the determined source path
        '--output', query_origin_dir
    ]

    print(f"[Iteration Control] Running command: {' '.join(command)}")
    
    try:
        import time
        start_time = time.time()
        result = subprocess.run(command, capture_output=True, text=True)
        end_time = time.time()
        running_time = end_time - start_time
        print(f"[Iteration Control] Running time: {running_time:.2f} seconds")
        
        # Save execution log
        output_log = {
            'command': ' '.join(command),
            'stdout': result.stdout,
            'stderr': result.stderr,
            'returncode': result.returncode,
            'running_time': running_time
        }
        
        log_file = os.path.join(query_origin_dir, 'query_execution_log.json')
        with open(log_file, 'w') as f:
            json.dump(output_log, f, indent=2)
        
        # Parse results if successful
        if 'ERROR:' not in result.stderr:
            # Look for CSV file
            ql_name = os.path.splitext(original_ql_filename)[0]
            cwe_dir_name = os.path.basename(os.path.dirname(machine.context.original_ql_path))
            csv_file = os.path.join(query_origin_dir, f"{cwe_dir_name}_{ql_name}.csv")
            
            # SARIF file should be in the same directory as CSV
            sarif_file = csv_file.replace('.csv', '.sarif')
            
            threadflow_count = 0
            if os.path.exists(sarif_file):
                try:
                    with open(sarif_file, 'r', encoding='utf-8') as f:
                        sarif_data = json.load(f)
                    
                    for run in sarif_data.get('runs', []):
                        for result in run.get('results', []):
                            for code_flow in result.get('codeFlows', []):
                                threadflow_count += len(code_flow.get('threadFlows', []))
                    
                    print(f"[Iteration Control] Found SARIF with {threadflow_count} threadFlows")
                except Exception as e:
                    print(f"[Iteration Control] Error reading SARIF: {e}")
            
            if os.path.exists(csv_file):
                results = []
                import csv
                with open(csv_file, 'r') as f:
                    csv_reader = csv.DictReader(f)
                    for row in csv_reader:
                        results.append(row)
                
                # Store original result count - use threadFlow count if available
                result_count = threadflow_count if threadflow_count > 0 else len(results)
                machine.context.original_result_count = result_count
                # Set initial_result_count if this is the first iteration
                if machine.context.current_iteration == 1:
                    machine.context.initial_result_count = result_count
                    machine.context.previous_result_count = result_count
                
                # Perform evaluation if SARIF exists
                evaluation_metrics = {}
                if os.path.exists(sarif_file):
                    from QLWorkflow.util.evaluation_utils import evaluate_sarif_results
                    # Save good/bad results in the query_origin_dir
                    # Find the actual CWE directory in Juliet test suite
                    testcases_base = os.path.join(SCRIPT_DIR, 'juliet-test-suite-c', 'testcases')
                    source_base_dir = None
                    if os.path.exists(testcases_base):
                        for dirname in os.listdir(testcases_base):
                            if dirname.startswith(f'CWE{machine.context.cwe_number}_'):
                                source_base_dir = os.path.join(testcases_base, dirname)
                                break
                    
                    evaluation_metrics = evaluate_sarif_results(sarif_file, query_origin_dir, source_base_dir)
                    print(f"[Iteration Control] Evaluation: TP={evaluation_metrics['true_positive_count']}, FP={evaluation_metrics['false_positive_count']}")
                    print(f"[Iteration Control] Saved good_results.json and bad_results.json to {query_origin_dir}")
                
                # Save results summary with evaluation
                results_summary = {
                    'ql_file': machine.context.original_ql_path,
                    'result_count': result_count,
                    'threadflow_count': threadflow_count,
                    'csv_count': len(results),
                    'csv_file': csv_file,
                    'sarif_file': sarif_file if os.path.exists(sarif_file) else None
                }
                
                # Add evaluation metrics if available
                if evaluation_metrics:
                    results_summary.update(evaluation_metrics)
                
                summary_file = os.path.join(query_origin_dir, 'results_log.json')
                with open(summary_file, 'w') as f:
                    json.dump(results_summary, f, indent=2)
                
                print(f"[Iteration Control] Original query completed. Results: {result_count} (threadFlows: {threadflow_count}, CSV rows: {len(results)})")
            else:
                machine.context.original_result_count = 0
                # Set initial_result_count if this is the first iteration
                if machine.context.current_iteration == 1:
                    machine.context.initial_result_count = 0
                    machine.context.previous_result_count = 0
                print(f"[Iteration Control] Original query completed. No results found.")
        else:
            print(f"[Iteration Control] Original query failed with errors")
            machine.context.original_result_count = 0
            # Set initial_result_count if this is the first iteration
            if machine.context.current_iteration == 1:
                machine.context.initial_result_count = 0
                machine.context.previous_result_count = 0
            
    except Exception as e:
        print(f"[Iteration Control] Error running original query: {str(e)}")
        machine.context.original_result_count = 0
        # Set initial_result_count if this is the first iteration
        if machine.context.current_iteration == 1:
            machine.context.initial_result_count = 0
            machine.context.previous_result_count = 0
    
    return "Origin query executed"


def run_modify_query_action(machine):
    """
    Run the query modification sub-workflow.
    """
    # Prepare previous results for modification context based on validation conclusion
    previous_results = {}
    if machine.context.iteration_history:
        last_iteration = machine.context.iteration_history[-1]
        validation = last_iteration.get('validation', {})
        
        # Use the result_category from validation to determine the modification type
        result_category = validation.get('result_category', '')
        
        if result_category == 'compile_error':
            previous_results['compile_error'] = True
            previous_results['error_message'] = validation.get('error_message', '')
        elif result_category == 'result_decrease':
            previous_results['result_decreased'] = True
            previous_results['previous_count'] = validation.get('previous_count', 0)
            previous_results['current_count'] = validation.get('current_count', 0)
    
    # For first iteration, use the original QL path (already converted to project path)
    # For subsequent iterations, use the current QL path
    if machine.context.current_iteration == 1:
        ql_path = machine.context.original_ql_path
    else:
        ql_path = machine.context.current_ql_path
    
    # Create context for modification
    modification_context = ModificationContext(
        cwe_number=machine.context.cwe_number,
        ql_file_path=ql_path,
        current_iteration=machine.context.current_iteration,
        query_name=machine.context.query_name,
        previous_results=previous_results,
        output_dir=machine.context.output_dir,
        working_directory=machine.context.output_dir,  # Explicitly set working_directory
        original_ql_path=machine.context.original_ql_path  # Pass original_ql_path for path resolution
    )
    
    # Run modification state machine
    result = call_sub_state_machine_action(
        sub_state_definitions=modification_states,
        sub_initial_state='ModifyQLQuery',
        sub_context_cls=lambda: modification_context,
        save_option='result'
    )(machine)
    
    # Update context with modified query path from the sub-context
    if modification_context.modified_ql_path:
        machine.context.current_ql_path = modification_context.modified_ql_path
    
    return "Query modified"


def run_execute_query_action(machine):
    """
    Run the query execution sub-workflow.
    """
    # Use the modified query from current iteration's query_results directory
    iteration_dir = os.path.join(machine.context.output_dir, f"iteration_{machine.context.current_iteration}")
    query_results_dir = os.path.join(iteration_dir, "query_results")
    ql_filename = os.path.basename(machine.context.original_ql_path)
    ql_path_to_use = os.path.join(query_results_dir, ql_filename)
    
    # Check if the modified query exists, if not use the current_ql_path
    if not os.path.exists(ql_path_to_use):
        print(f"[Iteration Control] Warning: Modified query not found at {ql_path_to_use}")
        # Try to use current_ql_path if available
        if hasattr(machine.context, 'current_ql_path') and machine.context.current_ql_path:
            ql_path_to_use = machine.context.current_ql_path
            print(f"[Iteration Control] Using current_ql_path: {ql_path_to_use}")
        else:
            # Fall back to original QL path
            ql_path_to_use = machine.context.original_ql_path
            print(f"[Iteration Control] Falling back to original QL path: {ql_path_to_use}")
    
    # Create context for query execution
    query_context = QueryContext(
        cwe_number=machine.context.cwe_number,
        ql_file_path=ql_path_to_use,
        current_iteration=machine.context.current_iteration,
        previous_result_count=machine.context.previous_result_count,
        output_dir=machine.context.output_dir,
        original_ql_path=machine.context.original_ql_path
    )
    
    # Run query execution state machine
    result = call_sub_state_machine_action(
        sub_state_definitions=query_states,
        sub_initial_state='RunQLQuery',
        sub_context_cls=lambda: query_context,
        save_option='result'
    )(machine)
    
    # Update context with results from the sub-context
    machine.context.current_result_count = query_context.result_count
    if hasattr(query_context, 'result_distribution'):
        machine.context.result_distribution = query_context.result_distribution
    
    print(f"[Iteration Control] Query execution completed. Result count: {machine.context.current_result_count}")
    return "Query executed"


def run_validate_output_action(machine):
    """
    Run the output validation sub-workflow.
    """
    # Construct the correct paths to the actual query files
    iteration_dir = os.path.join(machine.context.output_dir, f"iteration_{machine.context.current_iteration}")
    ql_filename = os.path.basename(machine.context.original_ql_path)
    
    # Paths to the actual query files in the iteration directories
    # For iteration 1, original is in initial/query_results/; for others, it's from previous iteration
    if machine.context.current_iteration == 1:
        original_ql_file = os.path.join(machine.context.output_dir, "initial", "query_results", ql_filename)
    else:
        prev_iteration = machine.context.current_iteration - 1
        original_ql_file = os.path.join(machine.context.output_dir, f"iteration_{prev_iteration}", "query_results", ql_filename)
    
    modified_ql_file = os.path.join(iteration_dir, "query_results", ql_filename)
    
    # Create context for validation
    validation_context = ValidationContext(
        cwe_number=machine.context.cwe_number,
        current_iteration=machine.context.current_iteration,
        query_name=machine.context.query_name,
        current_result_count=machine.context.current_result_count,
        previous_result_count=machine.context.previous_result_count,
        initial_result_count=getattr(machine.context, 'initial_result_count', 0),
        result_distribution=getattr(machine.context, 'result_distribution', {}),
        original_ql_file=original_ql_file,
        modified_ql_file=modified_ql_file,
        output_dir=machine.context.output_dir,
        working_directory=machine.context.output_dir  # Explicitly set working_directory
    )
    
    # Run validation state machine
    result = call_sub_state_machine_action(
        sub_state_definitions=validation_states,
        sub_initial_state='CheckQueryResults',
        sub_context_cls=lambda: validation_context,
        save_option='result'
    )(machine)
    
    # Update context with validation conclusion from the sub-context
    # The sub-context's validation_conclusion is returned as the result
    machine.context.last_validation = validation_context.validation_conclusion
    
    return "Validation completed"


def update_iteration_state_action(machine):
    """
    Update the iteration state based on validation results.
    """
    print(f"\n[Iteration Control] Updating iteration state for CWE-{machine.context.cwe_number}")
    
    # Record current iteration in history
    iteration_record = {
        'iteration': machine.context.current_iteration,
        'ql_path': machine.context.current_ql_path,
        'result_count': machine.context.current_result_count,
        'validation': machine.context.last_validation
    }
    machine.context.iteration_history.append(iteration_record)
    
    # Check if we should continue based on validation result
    if machine.context.last_validation is None:
        # If validation failed for some reason, stop
        machine.context.stop_reason = "Validation failed"
        return "stop"
    
    result_category = machine.context.last_validation.get('result_category', '')
    should_continue = machine.context.last_validation.get('continue_iteration', False)
    stop_reason = machine.context.last_validation.get('stop_reason', '')
    
    # Check if result count successfully increased
    if result_category == 'success_increase':
        machine.context.stop_reason = "Result count successfully increased"
        print(f"[Iteration Control] Success! Stopping iterations. {machine.context.stop_reason}")
        return "stop"
    
    # Otherwise check the continue flag
    if not should_continue:
        machine.context.stop_reason = stop_reason or "Validation recommends stopping"
        print(f"[Iteration Control] Stopping iterations. Reason: {machine.context.stop_reason}")
        return "stop"
    
    # Update for next iteration
    machine.context.previous_result_count = machine.context.current_result_count
    machine.context.current_iteration += 1
    
    print(f"[Iteration Control] Continuing to iteration {machine.context.current_iteration} (reason: {stop_reason})")
    return "continue"


def generate_final_report_action(machine):
    """
    Generate a final report summarizing all iterations.
    """
    print(f"\n[Iteration Control] Generating final report for CWE-{machine.context.cwe_number}")
    
    # Get initial evaluation metrics from initial/query_results/results_log.json
    initial_evaluation_metrics = {}
    initial_results_log_path = os.path.join(
        machine.context.output_dir,
        "initial",
        "query_results",
        "results_log.json"
    )
    
    if os.path.exists(initial_results_log_path):
        try:
            with open(initial_results_log_path, 'r') as f:
                initial_results_log = json.load(f)
            
            # Extract initial evaluation metrics
            if 'true_positive_count' in initial_results_log:
                initial_evaluation_metrics = {
                    'true_positive_count': initial_results_log.get('true_positive_count', 0),
                    'false_positive_count': initial_results_log.get('false_positive_count', 0),
                    'unknown_result_count': initial_results_log.get('unknown_result_count', 0),
                    'true_positive_rate': initial_results_log.get('true_positive_rate', 0),
                    'false_positive_rate': initial_results_log.get('false_positive_rate', 0),
                    'good_result_count': initial_results_log.get('good_result_count', 0),
                    'bad_result_count': initial_results_log.get('bad_result_count', 0),
                    'total_threadflows': initial_results_log.get('total_threadflows', 0)
                }
                print(f"[Iteration Control] Found initial evaluation metrics")
        except Exception as e:
            print(f"[Iteration Control] Error reading initial evaluation metrics: {e}")
    
    # Get final evaluation metrics from the last iteration's results_log.json
    final_evaluation_metrics = {}
    
    # Try to get evaluation metrics from the last iteration
    if machine.context.iteration_history:
        last_iteration = machine.context.iteration_history[-1]
        last_iteration_num = last_iteration['iteration']
        
        # Look for results_log.json in the last iteration's query_results
        results_log_path = os.path.join(
            machine.context.output_dir, 
            f"iteration_{last_iteration_num}", 
            "query_results", 
            "results_log.json"
        )
        
        if os.path.exists(results_log_path):
            try:
                with open(results_log_path, 'r') as f:
                    results_log = json.load(f)
                
                # Extract evaluation metrics
                if 'true_positive_count' in results_log:
                    final_evaluation_metrics = {
                        'true_positive_count': results_log.get('true_positive_count', 0),
                        'false_positive_count': results_log.get('false_positive_count', 0),
                        'unknown_result_count': results_log.get('unknown_result_count', 0),
                        'true_positive_rate': results_log.get('true_positive_rate', 0),
                        'false_positive_rate': results_log.get('false_positive_rate', 0),
                        'good_result_count': results_log.get('good_result_count', 0),
                        'bad_result_count': results_log.get('bad_result_count', 0),
                        'total_threadflows': results_log.get('total_threadflows', 0)
                    }
                    print(f"[Iteration Control] Found evaluation metrics from iteration {last_iteration_num}")
            except Exception as e:
                print(f"[Iteration Control] Error reading evaluation metrics: {e}")
    
    # Fall back to context evaluation_metrics if available
    if not final_evaluation_metrics and hasattr(machine.context, 'evaluation_metrics'):
        final_evaluation_metrics = machine.context.evaluation_metrics
    
    # Base report structure with evaluation
    report = {
        'cwe_number': machine.context.cwe_number,
        'original_ql_file': machine.context.original_ql_path,
        'total_iterations': len(machine.context.iteration_history),
        'stop_reason': machine.context.stop_reason,
        'iterations': machine.context.iteration_history,
        'final_result_count': machine.context.current_result_count,
        'initial_result_count': machine.context.initial_result_count,
        'overall_improvement': {
            'absolute': machine.context.current_result_count - machine.context.initial_result_count,
            'percentage': ((machine.context.current_result_count - machine.context.initial_result_count) / 
                         machine.context.initial_result_count * 100) if machine.context.initial_result_count > 0 else 0
        }
    }
    
    # Add evaluation metrics with clear initial/final naming
    if initial_evaluation_metrics:
        report['initial_true_positive'] = initial_evaluation_metrics.get('true_positive_count', 0)
        report['initial_false_positive'] = initial_evaluation_metrics.get('false_positive_count', 0)
        report['initial_unknown_result'] = initial_evaluation_metrics.get('unknown_result_count', 0)
        report['initial_true_positive_rate'] = initial_evaluation_metrics.get('true_positive_rate', 0)
        report['initial_false_positive_rate'] = initial_evaluation_metrics.get('false_positive_rate', 0)
        report['initial_good_result'] = initial_evaluation_metrics.get('good_result_count', 0)
        report['initial_bad_result'] = initial_evaluation_metrics.get('bad_result_count', 0)
        print(f"[Iteration Control] Added initial evaluation metrics: TP={initial_evaluation_metrics.get('true_positive_count', 0)}, FP={initial_evaluation_metrics.get('false_positive_count', 0)}")
    
    if final_evaluation_metrics:
        report['final_true_positive'] = final_evaluation_metrics.get('true_positive_count', 0)
        report['final_false_positive'] = final_evaluation_metrics.get('false_positive_count', 0)
        report['final_unknown_result'] = final_evaluation_metrics.get('unknown_result_count', 0)
        report['final_true_positive_rate'] = final_evaluation_metrics.get('true_positive_rate', 0)
        report['final_false_positive_rate'] = final_evaluation_metrics.get('false_positive_rate', 0)
        report['final_good_result'] = final_evaluation_metrics.get('good_result_count', 0)
        report['final_bad_result'] = final_evaluation_metrics.get('bad_result_count', 0)
        report['final_total_threadflows'] = final_evaluation_metrics.get('total_threadflows', 0)
        print(f"[Iteration Control] Added final evaluation metrics: TP={final_evaluation_metrics.get('true_positive_count', 0)}, FP={final_evaluation_metrics.get('false_positive_count', 0)}")
    
    # Calculate improvement in TP/FP if both initial and final metrics are available
    if initial_evaluation_metrics and final_evaluation_metrics:
        initial_tp = initial_evaluation_metrics.get('true_positive_count', 0)
        final_tp = final_evaluation_metrics.get('true_positive_count', 0)
        initial_fp = initial_evaluation_metrics.get('false_positive_count', 0)
        final_fp = final_evaluation_metrics.get('false_positive_count', 0)
        
        report['true_positive_improvement'] = {
            'absolute': final_tp - initial_tp,
            'percentage': ((final_tp - initial_tp) / initial_tp * 100) if initial_tp > 0 else (100.0 if final_tp > 0 else 0.0)
        }
        report['false_positive_improvement'] = {
            'absolute': final_fp - initial_fp,
            'percentage': ((final_fp - initial_fp) / initial_fp * 100) if initial_fp > 0 else (100.0 if final_fp > 0 else 0.0)
        }
    
    # Log if no final evaluation metrics found
    if not final_evaluation_metrics:
        print(f"[Iteration Control] No evaluation metrics found for final report")
    
    # Save final report
    report_file = os.path.join(machine.context.output_dir, 'final_report.json')
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    machine.context.final_report = report
    
    return "Report generated"


# Removed run_initial_evaluation_action function


# Removed run_successful_iteration_evaluation_action function


# Removed update_final_report_with_evaluation_action function


def exit_action(machine):
    """Exit action - returns the final report."""
    return machine.context.final_report


# State machine configuration for iteration control
state_definitions = {
    'CheckIterationLimit': {
        'action': check_iteration_limit_action,
        'next_state_func': lambda result, machine: 'SaveOriginQuery' if result == 'continue' else 'GenerateFinalReport',
    },
    'SaveOriginQuery': {
        'action': save_origin_query_action,
        'next_state_func': lambda result, machine: 'ModifyQuery',
    },
    # Removed RunInitialEvaluation state
    'ModifyQuery': {
        'action': run_modify_query_action,
        'next_state_func': lambda result, machine: 'ExecuteQuery',
    },
    'ExecuteQuery': {
        'action': run_execute_query_action,
        'next_state_func': lambda result, machine: 'ValidateOutput',
    },
    'ValidateOutput': {
        'action': run_validate_output_action,
        'next_state_func': lambda result, machine: 'UpdateIterationState',
    },
    'UpdateIterationState': {
        'action': update_iteration_state_action,
        'next_state_func': lambda result, machine: 'CheckIterationLimit' if result == 'continue' else 'GenerateFinalReport',
    },
    'GenerateFinalReport': {
        'action': generate_final_report_action,
        'next_state_func': lambda result, machine: 'Exit',
    },
    # Removed evaluation states
    'Exit': {
        'action': exit_action,
        'next_state_func': None,
    },
}