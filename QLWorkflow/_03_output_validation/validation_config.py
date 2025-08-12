"""
Output Validation Configuration
Defines the state machine for validating query results and determining if broadening was successful.
"""

from BaseMachine.agent_action_utils import create_agent_action
import json
import os
import subprocess
from QLWorkflow.util.logging_utils import get_ql_workflow_log_path, get_action_type_from_prompt


def check_query_results_action(machine):
    """
    Check the query execution results and gather information.
    """
    print(f"\n[Output Validation] Checking query execution results for CWE-{machine.context.cwe_number} iteration {machine.context.current_iteration}")
    
    iteration_dir = os.path.join(machine.context.output_dir, f"iteration_{machine.context.current_iteration}")
    # Query execution log is now in query_results directory
    execution_log_file = os.path.join(iteration_dir, 'query_results', 'query_execution_log.json')
    
    if not os.path.exists(execution_log_file):
        machine.context.has_compilation_errors = False
        machine.context.compilation_errors = []
        return "no_execution_log"
    
    with open(execution_log_file, 'r') as f:
        execution_log = json.load(f)
    
    # Check for compilation errors in stderr
    stderr = execution_log.get('stderr', '')
    if 'ERROR:' in stderr:
        # Extract error messages
        error_lines = [line for line in stderr.split('\n') if 'ERROR:' in line]
        machine.context.compilation_errors = error_lines
        machine.context.has_compilation_errors = True
        print(f"[Output Validation] Found {len(error_lines)} compilation errors")
    else:
        machine.context.has_compilation_errors = False
        machine.context.compilation_errors = []
        print(f"[Output Validation] No compilation errors found")
    
    return "continue"


def analyze_results_action(machine):
    """
    Analyze the query results to determine if broadening was successful.
    """
    current_count = machine.context.current_result_count
    previous_count = machine.context.previous_result_count
    iteration = machine.context.current_iteration
    
    # Calculate improvement
    if previous_count > 0:
        improvement_percentage = ((current_count - previous_count) / previous_count) * 100
    else:
        improvement_percentage = 100 if current_count > 0 else 0
    
    # Check if query had compilation errors
    had_compilation_errors = getattr(machine.context, 'has_compilation_errors', False)
    
    # Prepare analysis data
    analysis = {
        'iteration': iteration,
        'current_result_count': current_count,
        'previous_result_count': previous_count,
        'improvement_percentage': improvement_percentage,
        'improved': current_count > previous_count,
        'result_distribution': machine.context.result_distribution,
        'had_compilation_errors': had_compilation_errors
    }
    
    machine.context.analysis_result = analysis
    
    # Save analysis
    iteration_dir = os.path.join(machine.context.output_dir, f"iteration_{iteration}")
    reports_dir = os.path.join(iteration_dir, 'reports')
    os.makedirs(reports_dir, exist_ok=True)
    analysis_file = os.path.join(reports_dir, 'validation_analysis.json')
    with open(analysis_file, 'w') as f:
        json.dump(analysis, f, indent=2)
    
    return "Analysis completed"


def generate_validation_report_action(machine):
    """
    Generate a validation report using chat mode.
    """
    analysis = machine.context.analysis_result
    
    # Use appropriate model based on mode
    model_name = 'azure-gpt4o'
    if hasattr(machine, 'mode') and machine.mode == 'agent':
        # Agent mode - potentially use different settings
        model_name = 'azure-gpt4o'
    
    prompt_template = """Analyze the CodeQL query results for CWE-{cwe_number} iteration {current_iteration}.

File Paths:
- Original QL File: {original_ql_file}
- Modified QL File: {modified_ql_file}
- Current Results CSV(Results of modified ql): {current_csv_file}
- Previous Results CSV(Results of original ql): {previous_csv_file}

Summary Data:
- Current Result Count: {current_result_count}
- Previous Result Count: {previous_result_count}
- Improvement: {improvement_percentage:.1f}%

Please provide:
1. A summary of whether the query broadening was successful
2. Analysis of the result distribution (are we getting meaningful results or just noise?)
3. Recommendations for the next iteration:
   - Should we continue broadening?
   - What specific aspects should be modified?
   - Are there any concerning patterns in the results?
4. Risk assessment: Are we maintaining the integrity of the security check while broadening?

Keep your analysis concise and actionable."""
    
    # Set up logging context for QLWorkflow
    log_context = {
        'cwe_number': machine.context.cwe_number,
        'query_name': machine.context.query_name if hasattr(machine.context, 'query_name') else f"CWE-{machine.context.cwe_number:03d}",
        'iteration': machine.context.current_iteration,
        'output_dir': machine.context.output_dir
    }
    
    # Get the log path and set action type
    log_path = get_ql_workflow_log_path(log_context)
    if log_path:
        machine.context.session_log_path = str(log_path)  # Convert Path to string
    machine.context.action_type = 'validation'
    
    # Use agent action for agent mode with streaming JSON logging enabled
    action = create_agent_action(
        prompt_template=prompt_template,
        save_option='both',
        system_prompt="You are a CodeQL validation expert. Analyze query results and provide recommendations. You have access to Read tool to examine the CSV files for detailed analysis.",
        allowed_tools=["Read", "Grep"],
        enable_stream_logging=True
    )

    # Find CSV file paths
    iteration_dir = os.path.join(machine.context.output_dir, f"iteration_{machine.context.current_iteration}")
    current_csv_file = None
    previous_csv_file = None
    
    # Find current CSV file in query_results
    current_results_dir = os.path.join(iteration_dir, "query_results")
    if os.path.exists(current_results_dir):
        for file in os.listdir(current_results_dir):
            if file.endswith('.csv'):
                current_csv_file = os.path.join(current_results_dir, file)
                break
    
    # Find previous CSV file - from initial/ for iteration 1, from previous iteration for others
    if machine.context.current_iteration == 1:
        previous_results_dir = os.path.join(machine.context.output_dir, "initial")
    else:
        prev_iteration = machine.context.current_iteration - 1
        previous_results_dir = os.path.join(machine.context.output_dir, f"iteration_{prev_iteration}", "query_results")
        
    if os.path.exists(previous_results_dir):
        for file in os.listdir(previous_results_dir):
            if file.endswith('.csv'):
                previous_csv_file = os.path.join(previous_results_dir, file)
                break
    
    # Format the prompt for saving
    formatted_prompt = prompt_template.format(
        cwe_number=machine.context.cwe_number,
        current_iteration=machine.context.current_iteration,
        current_result_count=analysis['current_result_count'],
        previous_result_count=analysis['previous_result_count'],
        improvement_percentage=analysis['improvement_percentage'],
        original_ql_file=machine.context.original_ql_file,
        modified_ql_file=machine.context.modified_ql_file,
        current_csv_file=current_csv_file or "No CSV file found",
        previous_csv_file=previous_csv_file or "No CSV file found"
    )
    
    # Save the prompt to iteration/reports directory
    iteration_dir = os.path.join(machine.context.output_dir, f"iteration_{machine.context.current_iteration}")
    reports_dir = os.path.join(iteration_dir, "reports")
    os.makedirs(reports_dir, exist_ok=True)
    prompt_file = os.path.join(reports_dir, "03_validation_prompt.txt")
    with open(prompt_file, 'w') as f:
        f.write(formatted_prompt)
    
    result = action(machine,
                  cwe_number=machine.context.cwe_number,
                  current_iteration=machine.context.current_iteration,
                  current_result_count=analysis['current_result_count'],
                  previous_result_count=analysis['previous_result_count'],
                  improvement_percentage=analysis['improvement_percentage'],
                  original_ql_file=machine.context.original_ql_file,
                  modified_ql_file=machine.context.modified_ql_file,
                  current_csv_file=current_csv_file or "No CSV file found",
                  previous_csv_file=previous_csv_file or "No CSV file found")
    
    # Save the response - agent mode returns a dict with 'response' key
    response_file = os.path.join(reports_dir, "03_validation_response.txt")
    if isinstance(result, dict) and 'response' in result:
        with open(response_file, 'w') as f:
            f.write(result['response'])
        # Store response for later use
        machine.context.validation_response = result['response']
    elif isinstance(result, str):
        with open(response_file, 'w') as f:
            f.write(result)
        machine.context.validation_response = result
    
    return result


def save_validation_conclusion_action(machine):
    """
    Save the validation conclusion and recommendations.
    """
    # Extract conclusion from agent response
    response = getattr(machine.context, 'validation_response', '')
    
    # Categorize the result based on requirements
    current_count = machine.context.current_result_count
    previous_count = machine.context.previous_result_count
    has_compile_error = machine.context.analysis_result.get('had_compilation_errors', False)
    query_failed = machine.context.analysis_result.get('query_failed', False)
    
    # Determine result category
    if has_compile_error and query_failed:
        result_category = "compile_error"
        continue_iteration = True  # Continue to fix errors
        stop_reason = "Compilation errors need to be fixed"
    elif current_count > machine.context.initial_result_count:
        result_category = "success_increase"
        continue_iteration = False  # Success, stop iteration
        stop_reason = "Successfully increased result count"
    elif current_count < machine.context.initial_result_count:
        result_category = "result_decrease"
        continue_iteration = True  # Continue with warning about decrease
        stop_reason = "Result count decreased, need different approach"
    else:
        result_category = "no_change"
        continue_iteration = True  # Continue trying
        stop_reason = "No change in results, continue iteration"
    
    conclusion = {
        'iteration': machine.context.current_iteration,
        'result_category': result_category,
        'success': result_category == "success_increase",
        'current_count': current_count,
        'previous_count': previous_count,
        'has_compile_error': has_compile_error,
        'error_message': '\n'.join(machine.context.compilation_errors) if has_compile_error else '',
        'continue_iteration': continue_iteration,
        'stop_reason': stop_reason
    }
    
    machine.context.validation_conclusion = conclusion
    
    # Save conclusion
    iteration_dir = os.path.join(machine.context.output_dir, f"iteration_{machine.context.current_iteration}")
    conclusion_file = os.path.join(iteration_dir, 'validation_conclusion.json')
    with open(conclusion_file, 'w') as f:
        json.dump(conclusion, f, indent=2)
    
    # Log the interaction
    log_prompt = f"Validation report for CWE-{machine.context.cwe_number} iteration {machine.context.current_iteration}"
    if machine.context.messages:
        response = machine.context.messages[-1]['content']
        machine.context.log_interaction('validation_report', log_prompt, response)
    
    return "Validation completed"


def exit_action(machine):
    """Exit action - returns the validation conclusion."""
    return machine.context.validation_conclusion


# State machine configuration for output validation
state_definitions = {
    'CheckQueryResults': {
        'action': check_query_results_action,
        'next_state_func': lambda result, machine: 'AnalyzeResults',
    },
    'AnalyzeResults': {
        'action': analyze_results_action,
        'next_state_func': lambda result, machine: 'GenerateValidationReport',
    },
    'GenerateValidationReport': {
        'action': generate_validation_report_action,
        'next_state_func': lambda result, machine: 'SaveConclusion',
    },
    'SaveConclusion': {
        'action': save_validation_conclusion_action,
        'next_state_func': lambda result, machine: 'Exit',
    },
    'Exit': {
        'action': exit_action,
        'next_state_func': None,
    },
}