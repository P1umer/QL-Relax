"""
Tools for Iteration Control
"""

import os
import json
from datetime import datetime


def create_iteration_directory(output_dir, iteration_number):
    """Create a directory for the current iteration."""
    iteration_dir = os.path.join(output_dir, f"iteration_{iteration_number}")
    os.makedirs(iteration_dir, exist_ok=True)
    return iteration_dir


def load_iteration_history(output_dir):
    """Load iteration history from previous runs."""
    history_file = os.path.join(output_dir, 'iteration_history.json')
    if os.path.exists(history_file):
        with open(history_file, 'r') as f:
            return json.load(f)
    return []


def save_iteration_history(output_dir, history):
    """Save iteration history to file."""
    history_file = os.path.join(output_dir, 'iteration_history.json')
    with open(history_file, 'w') as f:
        json.dump(history, f, indent=2)


def calculate_convergence_metrics(iteration_history):
    """Calculate metrics to determine if the iterations are converging."""
    if len(iteration_history) < 2:
        return None
    
    metrics = {
        'improvement_trend': [],
        'is_converging': False,
        'convergence_rate': 0
    }
    
    # Calculate improvement between consecutive iterations
    for i in range(1, len(iteration_history)):
        prev_count = iteration_history[i-1].get('result_count', 0)
        curr_count = iteration_history[i].get('result_count', 0)
        
        if prev_count > 0:
            improvement = ((curr_count - prev_count) / prev_count) * 100
        else:
            improvement = 100 if curr_count > 0 else 0
        
        metrics['improvement_trend'].append(improvement)
    
    # Check if improvements are decreasing (converging)
    if len(metrics['improvement_trend']) >= 2:
        recent_improvements = metrics['improvement_trend'][-3:]
        if all(imp < 20 for imp in recent_improvements):
            metrics['is_converging'] = True
        
        # Calculate average improvement rate
        metrics['convergence_rate'] = sum(recent_improvements) / len(recent_improvements)
    
    return metrics


def generate_iteration_summary(iteration_data):
    """Generate a summary for a single iteration."""
    summary = {
        'iteration_number': iteration_data.get('iteration', 0),
        'timestamp': datetime.now().isoformat(),
        'ql_file': os.path.basename(iteration_data.get('ql_path', '')),
        'results': {
            'count': iteration_data.get('result_count', 0),
            'validation_passed': iteration_data.get('validation', {}).get('success', False)
        },
        'next_action': 'continue' if iteration_data.get('validation', {}).get('continue_iteration', False) else 'stop'
    }
    
    return summary


def should_early_stop(iteration_history, current_iteration):
    """Determine if we should stop early based on convergence or other factors."""
    # Check for convergence
    convergence = calculate_convergence_metrics(iteration_history)
    if convergence and convergence['is_converging']:
        return True, "Iterations are converging with minimal improvement"
    
    # Check for oscillation (results going up and down)
    if len(iteration_history) >= 3:
        recent_counts = [h.get('result_count', 0) for h in iteration_history[-3:]]
        if recent_counts[0] < recent_counts[1] > recent_counts[2]:
            return True, "Results are oscillating"
    
    # Check for explosion (too many results)
    if iteration_history and iteration_history[-1].get('result_count', 0) > 1000:
        return True, "Result count exceeds reasonable threshold"
    
    return False, None