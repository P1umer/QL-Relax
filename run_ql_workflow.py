#!/usr/bin/env python3
"""
Main entry point for running the QL Workflow.
This script executes the pipeline that broadens QL queries iteratively.
"""

import sys
import os
import argparse
import json
import glob

# Get the directory of the script for relative paths
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

from BaseMachine import StateMachine
from QLWorkflow.pipeline_config import state_definitions, QLWorkflowContext
from QLWorkflow.util.evaluation_utils import evaluate_sarif_results


def run_evaluation_only(cwe_number, output_dir, specific_query=None):
    """
    Run evaluation only on existing SARIF files for a CWE.
    """
    print(f"\nRunning evaluation only for CWE-{cwe_number}")
    
    # Find SARIF files for this CWE
    cwe_dir = os.path.join(output_dir, f"CWE-{cwe_number}_*")
    cwe_dirs = glob.glob(cwe_dir)
    
    if not cwe_dirs:
        print(f"No directories found for CWE-{cwe_number} in {output_dir}")
        return
    
    results = []
    
    for cwe_path in cwe_dirs:
        # Skip if specific query is requested and this doesn't match
        if specific_query and specific_query not in os.path.basename(cwe_path):
            continue
            
        # Find all SARIF files in iterations and initial
        sarif_patterns = [
            os.path.join(cwe_path, "initial/query_results/*.sarif"),
            os.path.join(cwe_path, "iteration_*/query_results/*.sarif")
        ]
        
        for pattern in sarif_patterns:
            sarif_files = glob.glob(pattern)
            
            for sarif_file in sarif_files:
                print(f"\nEvaluating: {sarif_file}")
                
                # Get output directory for this SARIF
                query_results_dir = os.path.dirname(sarif_file)
                
                # Find source base directory for CWE
                testcases_base = os.path.join(SCRIPT_DIR, 'juliet-test-suite-c', 'testcases')
                source_base_dir = None
                if os.path.exists(testcases_base):
                    for dirname in os.listdir(testcases_base):
                        if dirname.startswith(f'CWE{cwe_number}_'):
                            source_base_dir = os.path.join(testcases_base, dirname)
                            break
                
                # Run evaluation
                evaluation_metrics = evaluate_sarif_results(sarif_file, query_results_dir, source_base_dir)
                
                # Update results_log.json
                results_log_path = os.path.join(query_results_dir, 'results_log.json')
                if os.path.exists(results_log_path):
                    with open(results_log_path, 'r') as f:
                        results_log = json.load(f)
                    
                    # Remove any existing error and update with evaluation metrics
                    if 'error' in results_log:
                        del results_log['error']
                    results_log.update(evaluation_metrics)
                    
                    # Update result_count based on SARIF threadflows
                    if 'total_threadflows' in evaluation_metrics:
                        results_log['result_count'] = evaluation_metrics['total_threadflows']
                    
                    with open(results_log_path, 'w') as f:
                        json.dump(results_log, f, indent=2)
                    
                    print(f"Updated: {results_log_path}")
                else:
                    # Create new results_log.json with evaluation metrics
                    results_log = {
                        'sarif_file': sarif_file,
                        **evaluation_metrics
                    }
                    
                    with open(results_log_path, 'w') as f:
                        json.dump(results_log, f, indent=2)
                    
                    print(f"Created: {results_log_path}")
                
                # Print evaluation results
                print(f"  Good results (FP): {evaluation_metrics['good_result_count']}")
                print(f"  Bad results (TP): {evaluation_metrics['bad_result_count']}")
                print(f"  Unknown results: {evaluation_metrics['unknown_result_count']}")
                print(f"  Total threadflows: {evaluation_metrics['total_threadflows']}")
                print(f"  True positive rate: {evaluation_metrics['true_positive_rate']}%")
                print(f"  False positive rate: {evaluation_metrics['false_positive_rate']}%")
                
                results.append({
                    'sarif_file': sarif_file,
                    'metrics': evaluation_metrics
                })
    
    if not results:
        print(f"\nNo SARIF files found for evaluation")
    else:
        print(f"\nEvaluated {len(results)} SARIF files")
        
        # Update final_report.json if it exists
        update_final_report_evaluation(cwe_number, output_dir, results, specific_query)
    
    return results


def update_final_report_evaluation(cwe_number, output_dir, eval_results, specific_query=None):
    """
    Update final_report.json files with evaluation metrics.
    """
    # Find final_report.json files for this CWE
    cwe_dir = os.path.join(output_dir, f"CWE-{cwe_number}_*")
    cwe_dirs = glob.glob(cwe_dir)
    
    for cwe_path in cwe_dirs:
        # Skip if specific query is requested and this doesn't match
        if specific_query and specific_query not in os.path.basename(cwe_path):
            continue
            
        final_report_path = os.path.join(cwe_path, 'final_report.json')
        if os.path.exists(final_report_path):
            try:
                with open(final_report_path, 'r') as f:
                    report_data = json.load(f)
                
                # Find evaluation metrics from the results for this specific CWE dir
                initial_metrics = None
                final_metrics = None
                
                # Get the query name from the directory
                dir_query_name = os.path.basename(cwe_path).split('_', 1)[1] if '_' in os.path.basename(cwe_path) else ''
                
                for result in eval_results:
                    sarif_file = result['sarif_file']
                    metrics = result['metrics']
                    
                    # Check if this result belongs to the current CWE directory
                    if dir_query_name and dir_query_name in sarif_file:
                        if '/initial/' in sarif_file:
                            initial_metrics = metrics
                        elif '/iteration_' in sarif_file:
                            # Use the last iteration as final metrics
                            final_metrics = metrics
                
                # Update report with evaluation metrics
                if initial_metrics:
                    report_data.update({
                        "initial_true_positive": initial_metrics['true_positive_count'],
                        "initial_false_positive": initial_metrics['false_positive_count'],
                        "initial_unknown_result": initial_metrics['unknown_result_count'],
                        "initial_true_positive_rate": initial_metrics['true_positive_rate'],
                        "initial_false_positive_rate": initial_metrics['false_positive_rate'],
                        "initial_good_result": initial_metrics['good_result_count'],
                        "initial_bad_result": initial_metrics['bad_result_count']
                    })
                    # Update initial_result_count based on threadflows
                    if 'total_threadflows' in initial_metrics:
                        report_data["initial_result_count"] = initial_metrics['total_threadflows']
                
                if final_metrics:
                    report_data.update({
                        "final_true_positive": final_metrics['true_positive_count'],
                        "final_false_positive": final_metrics['false_positive_count'],
                        "final_unknown_result": final_metrics['unknown_result_count'],
                        "final_true_positive_rate": final_metrics['true_positive_rate'],
                        "final_false_positive_rate": final_metrics['false_positive_rate'],
                        "final_good_result": final_metrics['good_result_count'],
                        "final_bad_result": final_metrics['bad_result_count'],
                        "final_total_threadflows": final_metrics['total_threadflows']
                    })
                    # Update final_result_count based on threadflows
                    if 'total_threadflows' in final_metrics:
                        report_data["final_result_count"] = final_metrics['total_threadflows']
                    
                    # Update iteration result counts based on eval results
                    if 'iterations' in report_data:
                        for iteration in report_data['iterations']:
                            # Find corresponding eval result for this iteration
                            for result in eval_results:
                                if f'iteration_{iteration["iteration"]}' in result['sarif_file']:
                                    iteration['result_count'] = result['metrics']['total_threadflows']
                                    if 'validation' in iteration:
                                        iteration['validation']['current_count'] = result['metrics']['total_threadflows']
                                    break
                    
                    # Calculate improvement
                    if initial_metrics:
                        initial_tp = initial_metrics['true_positive_count']
                        final_tp = final_metrics['true_positive_count']
                        initial_fp = initial_metrics['false_positive_count']
                        final_fp = final_metrics['false_positive_count']
                        initial_count = initial_metrics.get('total_threadflows', 0)
                        final_count = final_metrics.get('total_threadflows', 0)
                        
                        tp_improvement = final_tp - initial_tp
                        fp_improvement = final_fp - initial_fp
                        
                        report_data["true_positive_improvement"] = {
                            "absolute": tp_improvement,
                            "percentage": (tp_improvement / initial_tp * 100) if initial_tp > 0 else 0.0
                        }
                        
                        report_data["false_positive_improvement"] = {
                            "absolute": fp_improvement,
                            "percentage": (fp_improvement / initial_fp * 100) if initial_fp > 0 else 0.0
                        }
                        
                        # Update overall improvement
                        report_data["overall_improvement"] = {
                            "absolute": final_count - initial_count,
                            "percentage": ((final_count - initial_count) / initial_count * 100) if initial_count > 0 else 0.0 if final_count == 0 else 100.0
                        }
                
                # Save updated report
                with open(final_report_path, 'w') as f:
                    json.dump(report_data, f, indent=2)
                
                print(f"Updated: {final_report_path}")
                
            except Exception as e:
                print(f"Error updating final report {final_report_path}: {str(e)}")


def main():
    parser = argparse.ArgumentParser(description='Run QL Workflow for modifying CodeQL queries')
    parser.add_argument('--cwe', type=int,
                        help='CWE number to process')
    parser.add_argument('--all', action='store_true',
                        help='Process all available CWEs')
    parser.add_argument('--max-iterations', type=int, default=10,
                        help='Maximum number of iterations per QL file (default: 10)')
    parser.add_argument('--output-dir', type=str, 
                        default=os.path.join(SCRIPT_DIR, 'qlworkspace'),
                        help='Output directory for results and logs')
    parser.add_argument('--mode', type=str, default='agent',
                        help='Execution mode (default: agent)')
    parser.add_argument('--query', type=str,
                        help='Specific query name to run (e.g., TaintedAllocationSize)')
    parser.add_argument('--eval-only', action='store_true',
                        help='Only run evaluation on existing SARIF files without running queries')
    
    args = parser.parse_args()
    
    # Validate arguments
    if not args.all and not args.cwe:
        parser.error('Either --cwe or --all must be specified')
    if args.all and args.cwe:
        parser.error('Cannot specify both --cwe and --all options')
    if args.query and args.all:
        parser.error('--query can only be used with --cwe, not with --all')
    # Handle eval-only mode
    if args.eval_only:
        if args.all:
            # Run evaluation for all CWEs
            print("Running evaluation-only mode for all CWEs")
            
            # Find all CWE directories
            cwe_dirs = glob.glob(os.path.join(args.output_dir, "CWE-*"))
            cwe_numbers = set()
            
            for cwe_dir in cwe_dirs:
                # Extract CWE number from directory name
                dirname = os.path.basename(cwe_dir)
                if dirname.startswith("CWE-") and "_" in dirname:
                    cwe_num = dirname.split("-")[1].split("_")[0]
                    if cwe_num.isdigit():
                        cwe_numbers.add(int(cwe_num))
            
            # Run evaluation for each unique CWE
            for cwe_num in sorted(cwe_numbers):
                print(f"\n{'='*60}")
                print(f"Processing CWE-{cwe_num}")
                print(f"{'='*60}")
                run_evaluation_only(cwe_num, args.output_dir, None)
            
            return
        elif args.cwe:
            print(f"Running evaluation-only mode for CWE-{args.cwe}")
            if args.query:
                print(f"Filtering for query: {args.query}")
            
            run_evaluation_only(args.cwe, args.output_dir, args.query)
            return
        else:
            parser.error('--eval-only requires either --cwe or --all to be specified')
    
    # Create context
    context = QLWorkflowContext(
        max_iterations=args.max_iterations,
        output_dir=args.output_dir,
        specific_cwe=args.cwe,
        process_all_cwes=args.all,
        specific_query=args.query
    )
    
    # Create and run the state machine
    print(f"Starting QL Workflow...")
    if args.all:
        print(f"Processing: All CWEs")
    else:
        print(f"CWE: {args.cwe}")
    if args.query:
        print(f"Query: {args.query}")
    print(f"Max iterations: {args.max_iterations}")
    print(f"Output directory: {args.output_dir}")
    print(f"Mode: {args.mode} (using BaseMachine agent mode)")
    
    # Set config path
    config_path = os.path.join(SCRIPT_DIR, '.config/config.json')
    
    machine = StateMachine(
        state_definitions=state_definitions,
        initial_state='GetCommonCWEs',
        context=context,
        mode=args.mode,
        config_path=config_path
    )
    
    try:
        # Run the workflow
        machine.process()
        print("\nQL Workflow completed successfully!")
        
    except RuntimeError as e:
        if "Claude AI usage limit reached" in str(e):
            print("\n[STOPPED] Claude AI usage limit reached. Pipeline stopped gracefully.")
            print("The workflow was interrupted due to API rate limits.")
            print(f"Partial results saved to: {args.output_dir}")
            # Don't re-raise - exit gracefully
            return
        else:
            print(f"\nRuntime error in QL Workflow: {str(e)}")
            raise
    except Exception as e:
        print(f"\nError running QL Workflow: {str(e)}")
        raise


if __name__ == "__main__":
    main()