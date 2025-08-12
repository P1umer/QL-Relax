"""
QL Workflow Pipeline Configuration
Main pipeline that orchestrates the QL query broadening workflow.
"""

from BaseMachine.action_utils import call_sub_state_machine_action
import subprocess
import json
import os

# Get the absolute path of the script directory
SCRIPT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Import iteration control configuration
from QLWorkflow._04_iteration_control.iteration_config import state_definitions as iteration_states
from QLWorkflow._04_iteration_control.iteration_context import IterationContext

# Import query execution for initial baseline
from QLWorkflow._02_run_ql_query.query_config import state_definitions as query_states
from QLWorkflow._02_run_ql_query.query_context import QueryContext


class QLWorkflowContext:
    """
    Root context for the QL workflow pipeline.
    """
    
    def __init__(self, **kwargs):
        """
        Initialize the QL workflow context.
        
        Args:
            **kwargs: Configuration parameters
        """
        # Workflow configuration
        self.max_iterations = kwargs.get('max_iterations', 5)
        self.output_base_dir = kwargs.get('output_dir', os.path.join(SCRIPT_DIR, 'qlworkspace'))
        self.cwe_limit = kwargs.get('cwe_limit', None)
        self.specific_cwe = kwargs.get('specific_cwe', None)
        self.process_all_cwes = kwargs.get('process_all_cwes', False)
        self.specific_query = kwargs.get('specific_query', None)
        
        # CWE and QL data (will be populated by pipeline)
        self.common_cwes = []
        self.cwe_ql_mapping = {}
        self.current_cwe = None
        self.current_ql_files = []
        self.processed_cwes = set()  # Track processed CWEs for --all mode
        
        # Results tracking
        self.workflow_results = {}
        
        # For LLM interactions
        self.messages = []
    
    def __str__(self):
        return f"QLWorkflowContext(cwes={len(self.common_cwes)})"
    
    def __repr__(self):
        return self.__str__()


def get_common_cwes_action(machine):
    """
    Get the list of common CWEs using run_juliet.py --list-common-cwes.
    """
    command = ['python3', os.path.join(SCRIPT_DIR, 'run_juliet.py'), '--list-common-cwes']
    
    try:
        result = subprocess.run(command, capture_output=True, text=True)
        
        if result.returncode != 0:
            return f"Failed to get common CWEs: {result.stderr}"
        
        # Parse the output to extract CWE numbers and QL files
        output_lines = result.stdout.split('\n')
        current_cwe = None
        cwe_ql_mapping = {}
        
        for line in output_lines:
            if line.startswith('CWE-'):
                # Extract CWE number
                cwe_num = int(line.split('-')[1].split(':')[0])
                current_cwe = cwe_num
                cwe_ql_mapping[current_cwe] = []
            elif line.strip().startswith('- /') and current_cwe:
                # Extract QL file path
                ql_path = line.strip().lstrip('- ')
                # Skip _after.ql and _temp files created by the workflow
                if not ql_path.endswith('_after.ql') and '_temp_' not in ql_path:
                    cwe_ql_mapping[current_cwe].append(ql_path)
        
        machine.context.common_cwes = sorted(cwe_ql_mapping.keys())
        machine.context.cwe_ql_mapping = cwe_ql_mapping
        
        # Save the mapping
        os.makedirs(machine.context.output_base_dir, exist_ok=True)
        mapping_file = os.path.join(machine.context.output_base_dir, 'cwe_ql_mapping.json')
        with open(mapping_file, 'w') as f:
            json.dump(cwe_ql_mapping, f, indent=2)
        
        return f"Found {len(machine.context.common_cwes)} common CWEs"
        
    except Exception as e:
        return f"Error getting common CWEs: {str(e)}"


def select_next_cwe_action(machine):
    """
    Select the next CWE to process.
    """
    if machine.context.process_all_cwes:
        # Process all CWEs mode
        for cwe in machine.context.common_cwes:
            if cwe not in machine.context.processed_cwes:
                machine.context.current_cwe = cwe
                machine.context.current_ql_files = machine.context.cwe_ql_mapping[cwe]
                
                # Filter by specific query if provided
                if machine.context.specific_query:
                    filtered_files = [f for f in machine.context.current_ql_files 
                                    if machine.context.specific_query in os.path.basename(f)]
                    if filtered_files:
                        machine.context.current_ql_files = filtered_files
                    else:
                        print(f"Warning: Query '{machine.context.specific_query}' not found for CWE-{cwe}")
                        continue
                
                machine.context.processed_cwes.add(cwe)
                return f"Selected CWE-{cwe} with {len(machine.context.current_ql_files)} QL files"
        
        # All CWEs processed
        return "all_processed"
    
    else:
        # Process specific CWE (original behavior)
        if machine.context.specific_cwe:
            if machine.context.specific_cwe in machine.context.common_cwes:
                if machine.context.specific_cwe not in machine.context.workflow_results:
                    machine.context.current_cwe = machine.context.specific_cwe
                    machine.context.current_ql_files = machine.context.cwe_ql_mapping[machine.context.specific_cwe]
                    
                    # Filter by specific query if provided
                    if machine.context.specific_query:
                        filtered_files = [f for f in machine.context.current_ql_files 
                                        if machine.context.specific_query in os.path.basename(f)]
                        if filtered_files:
                            machine.context.current_ql_files = filtered_files
                        else:
                            return f"Error: Query '{machine.context.specific_query}' not found for CWE-{machine.context.specific_cwe}"
                    
                    return f"Selected CWE-{machine.context.specific_cwe} with {len(machine.context.current_ql_files)} QL files"
                else:
                    return "all_processed"  # Already processed
            else:
                return f"CWE-{machine.context.specific_cwe} not found in common CWEs"
        
        # Since we're only processing one specific CWE, we're done
        return "all_processed"


def process_cwe_ql_files_action(machine):
    """
    Process all QL files for the current CWE.
    """
    cwe = machine.context.current_cwe
    ql_files = machine.context.current_ql_files
    cwe_results = []
    
    print(f"\n{'='*80}")
    print(f"[Pipeline] Processing CWE-{cwe} with {len(ql_files)} QL file(s)")
    print(f"{'='*80}")
    
    for ql_file in ql_files:
        print(f"\n[Pipeline] Processing {ql_file} for CWE-{cwe}")
        
        # Create output directory for this CWE and QL file
        ql_name = os.path.splitext(os.path.basename(ql_file))[0]
        output_dir = os.path.join(machine.context.output_base_dir, f"CWE-{cwe:03d}_{ql_name}")
        os.makedirs(output_dir, exist_ok=True)
        
        # Initialize - the initial count will be determined in the first iteration
        initial_count = 0  # Will be set by save_origin_query_action in iteration 1
        print(f"[Pipeline] Starting iterations for {ql_file}")
        
        # Run the iteration workflow starting from iteration 1
        iteration_context = IterationContext(
            cwe_number=cwe,
            ql_file_path=ql_file,
            query_name=ql_name,
            max_iterations=machine.context.max_iterations,
            initial_result_count=initial_count,
            output_dir=output_dir
        )
        iteration_context.current_iteration = 1  # Start from iteration 1
        
        # Convert origin path to project codeql path
        if 'qlworkspace/origin/codeql/' in ql_file:
            # Extract the relative path after origin/codeql/
            relative_path = ql_file.split('qlworkspace/origin/codeql/')[-1]
            
            # Construct the project codeql path
            project_codeql_path = os.path.join(output_dir, 'codeql', relative_path)
            project_codeql_path = os.path.abspath(project_codeql_path)
            
            # Check if the file exists in project codeql directory
            if os.path.exists(project_codeql_path):
                iteration_context.original_ql_path = project_codeql_path
                print(f"[Pipeline] Using project CodeQL file: {project_codeql_path}")
            else:
                # Fallback to original if project copy doesn't exist
                iteration_context.original_ql_path = ql_file
                print(f"[Pipeline] WARNING: Project CodeQL file not found at {project_codeql_path}")
                print(f"[Pipeline] Using original: {ql_file}")
        else:
            iteration_context.original_ql_path = ql_file
        
        iteration_result = call_sub_state_machine_action(
            sub_state_definitions=iteration_states,
            sub_initial_state='CheckIterationLimit',
            sub_context_cls=lambda: iteration_context,
            save_option='result'
        )(machine)
        
        # Store results
        ql_result = {
            'ql_file': ql_file,
            'initial_count': initial_count,
            'final_report': iteration_context.final_report or {}
        }
        cwe_results.append(ql_result)
    
    # Store CWE results
    machine.context.workflow_results[cwe] = cwe_results
    
    # Save intermediate results
    results_file = os.path.join(machine.context.output_base_dir, 'workflow_results.json')
    with open(results_file, 'w') as f:
        json.dump(machine.context.workflow_results, f, indent=2)
    
    return f"Processed {len(ql_files)} QL files for CWE-{cwe}"


def generate_summary_report_action(machine):
    """
    Generate a summary report for the processed CWE.
    """
    if not machine.context.workflow_results:
        print("\nNo results to summarize")
        return "No results"
    
    summary = {
        'total_cwes': len(machine.context.workflow_results),
        'total_ql_files': sum(len(results) for results in machine.context.workflow_results.values()),
        'cwe_summaries': {}
    }
    
    for cwe, ql_results in machine.context.workflow_results.items():
        cwe_summary = {
            'ql_files_processed': len(ql_results),
            'total_improvement': 0,
            'successful_modifications': 0,
            'compilation_failures': 0,
            'result_decreases': 0
        }
        
        for ql_result in ql_results:
            final_report = ql_result.get('final_report', {})
            improvement = final_report.get('overall_improvement', {})
            
            # Check the final iteration's result category
            iterations = final_report.get('iterations', [])
            if iterations:
                last_iteration = iterations[-1]
                validation = last_iteration.get('validation', {})
                result_category = validation.get('result_category', '')
                
                if result_category == 'success_increase':
                    cwe_summary['successful_modifications'] += 1
                    cwe_summary['total_improvement'] += improvement.get('percentage', 0)
                elif result_category == 'compile_error':
                    cwe_summary['compilation_failures'] += 1
                elif result_category == 'result_decrease':
                    cwe_summary['result_decreases'] += 1
        
        summary['cwe_summaries'][f'CWE-{cwe}'] = cwe_summary
    
    # Save summary
    summary_file = os.path.join(machine.context.output_base_dir, 'workflow_summary.json')
    with open(summary_file, 'w') as f:
        json.dump(summary, f, indent=2)
    
    print(f"\nWorkflow Summary saved to: {summary_file}")
    return "Summary generated"


def exit_action(machine):
    """Exit action."""
    return None


# Root workflow state machine configuration
state_definitions = {
    'GetCommonCWEs': {
        'action': get_common_cwes_action,
        'next_state_func': lambda result, machine: 'SelectNextCWE',
    },
    'SelectNextCWE': {
        'action': select_next_cwe_action,
        'next_state_func': lambda result, machine: 'ProcessCWEQLFiles' if result != 'all_processed' else 'GenerateSummary',
    },
    'ProcessCWEQLFiles': {
        'action': process_cwe_ql_files_action,
        'next_state_func': lambda result, machine: 'SelectNextCWE',
    },
    'GenerateSummary': {
        'action': generate_summary_report_action,
        'next_state_func': lambda result, machine: 'Exit',
    },
    'Exit': {
        'action': exit_action,
        'next_state_func': None,
    },
}