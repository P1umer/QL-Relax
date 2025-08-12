"""
Tools for Output Validation
"""

import json
import os
import csv


def calculate_metrics(current_count, previous_count):
    """Calculate improvement metrics."""
    metrics = {
        'absolute_change': current_count - previous_count,
        'percentage_change': 0,
        'multiplier': 1
    }
    
    if previous_count > 0:
        metrics['percentage_change'] = ((current_count - previous_count) / previous_count) * 100
        metrics['multiplier'] = current_count / previous_count
    elif current_count > 0:
        metrics['percentage_change'] = 100
        metrics['multiplier'] = float('inf')
    
    return metrics


def assess_result_quality(result_distribution, total_count):
    """Assess the quality of results based on distribution."""
    quality_indicators = {
        'concentration_score': 0,  # How concentrated are the results
        'diversity_score': 0,      # How diverse are the results
        'likely_noise': False
    }
    
    if not result_distribution or total_count == 0:
        return quality_indicators
    
    # Calculate concentration (Gini coefficient approximation)
    sorted_counts = sorted(result_distribution.values(), reverse=True)
    cumulative_sum = 0
    for i, count in enumerate(sorted_counts):
        cumulative_sum += count * (i + 1)
    
    if sum(sorted_counts) > 0:
        quality_indicators['concentration_score'] = (2 * cumulative_sum) / (len(sorted_counts) * sum(sorted_counts)) - 1
    
    # Calculate diversity
    quality_indicators['diversity_score'] = len(result_distribution) / total_count
    
    # Check for likely noise (too many unique results)
    if quality_indicators['diversity_score'] > 0.8:
        quality_indicators['likely_noise'] = True
    
    return quality_indicators


def generate_iteration_summary(iteration_data):
    """Generate a summary for the iteration."""
    summary = {
        'iteration': iteration_data.get('iteration', 0),
        'timestamp': iteration_data.get('timestamp', ''),
        'results': {
            'count': iteration_data.get('current_count', 0),
            'improvement': iteration_data.get('improvement_percentage', 0),
            'quality': iteration_data.get('quality_assessment', {})
        },
        'recommendation': iteration_data.get('recommendation', 'Continue iteration'),
        'key_findings': []
    }
    
    # Add key findings based on data
    if summary['results']['improvement'] > 50:
        summary['key_findings'].append('Significant improvement in result count')
    
    if iteration_data.get('quality_assessment', {}).get('likely_noise', False):
        summary['key_findings'].append('Results may contain noise - consider refining constraints')
    
    return summary


def should_continue_iteration(validation_conclusion, current_iteration, max_iterations=5):
    """Determine if iteration should continue."""
    # Check max iterations
    if current_iteration >= max_iterations:
        return False, "Maximum iterations reached"
    
    # Check improvement
    if not validation_conclusion.get('success', False):
        return False, "No improvement in results"
    
    # Check for diminishing returns
    analysis = validation_conclusion.get('agent_analysis', '')
    if 'noise' in analysis.lower() or 'too broad' in analysis.lower():
        return False, "Query may be too broad"
    
    # Check explicit recommendation
    if not validation_conclusion.get('continue_iteration', True):
        return False, "Validation recommends stopping"
    
    return True, "Continue with next iteration"