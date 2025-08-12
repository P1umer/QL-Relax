#!/usr/bin/env python3
"""
Plot initial vs final results comparison charts.
"""

import os
import json
import glob
import matplotlib.pyplot as plt
import numpy as np
from collections import defaultdict
import argparse

def collect_initial_and_final_results(qlworkspace_dir):
    """Collect both initial and final results from all CWE directories."""
    initial_results = []
    final_results = []
    
    # Find all CWE directories
    cwe_pattern = os.path.join(qlworkspace_dir, "CWE-*")
    cwe_dirs = glob.glob(cwe_pattern)
    
    for cwe_dir in cwe_dirs:
        cwe_name = os.path.basename(cwe_dir)
        if '_' in cwe_name:
            cwe_part, query_part = cwe_name.split('_', 1)
            cwe_number = cwe_part.replace('CWE-', '')
            query_name = query_part
        else:
            continue
        
        # Collect initial results
        initial_pattern = os.path.join(cwe_dir, "initial/query_results/results_log.json")
        initial_files = glob.glob(initial_pattern)
        
        initial_data = None
        for log_file in initial_files:
            try:
                with open(log_file, 'r') as f:
                    data = json.load(f)
                
                if data.get('total_threadflows', 0) > 0 and 'error' not in data:
                    initial_data = {
                        'cwe': cwe_number,
                        'query': query_name,
                        'tp': data.get('true_positive_count', 0),
                        'fp': data.get('false_positive_count', 0),
                        'total': data.get('total_threadflows', 0),
                        'tp_rate': data.get('true_positive_rate', 0.0),
                        'fp_rate': data.get('false_positive_rate', 0.0)
                    }
                    break
            except:
                continue
        
        # Collect final results (prefer latest iteration)
        final_pattern = os.path.join(cwe_dir, "iteration_*/query_results/results_log.json")
        final_files = sorted(glob.glob(final_pattern), reverse=True)  # Latest first
        
        final_data = None
        for log_file in final_files:
            try:
                with open(log_file, 'r') as f:
                    data = json.load(f)
                
                if data.get('total_threadflows', 0) > 0 and 'error' not in data:
                    final_data = {
                        'cwe': cwe_number,
                        'query': query_name,
                        'tp': data.get('true_positive_count', 0),
                        'fp': data.get('false_positive_count', 0),
                        'total': data.get('total_threadflows', 0),
                        'tp_rate': data.get('true_positive_rate', 0.0),
                        'fp_rate': data.get('false_positive_rate', 0.0)
                    }
                    break
            except:
                continue
        
        # Only include if we have both initial and final data
        if initial_data and final_data:
            initial_results.append(initial_data)
            final_results.append(final_data)
        elif initial_data:  # Only initial data available
            initial_results.append(initial_data)
            # Create empty final data for comparison
            final_results.append({
                'cwe': cwe_number,
                'query': query_name,
                'tp': 0, 'fp': 0, 'total': 0,
                'tp_rate': 0.0, 'fp_rate': 0.0
            })
        elif final_data:  # Only final data available
            final_results.append(final_data)
            # Create empty initial data for comparison
            initial_results.append({
                'cwe': cwe_number,
                'query': query_name,
                'tp': 0, 'fp': 0, 'total': 0,
                'tp_rate': 0.0, 'fp_rate': 0.0
            })
    
    return initial_results, final_results

def create_comparison_chart(initial_results, final_results, output_path):
    """Create side-by-side comparison charts."""
    if not initial_results and not final_results:
        print("No data to plot")
        return
    
    # Ensure both lists have the same length and order
    all_queries = set()
    initial_dict = {f"{r['cwe']}_{r['query']}": r for r in initial_results}
    final_dict = {f"{r['cwe']}_{r['query']}": r for r in final_results}
    all_queries = set(initial_dict.keys()) | set(final_dict.keys())
    
    # Prepare aligned data
    aligned_initial = []
    aligned_final = []
    
    for query_key in sorted(all_queries):
        initial_data = initial_dict.get(query_key, {
            'cwe': query_key.split('_')[0], 'query': '_'.join(query_key.split('_')[1:]),
            'tp': 0, 'fp': 0, 'total': 0, 'tp_rate': 0.0
        })
        final_data = final_dict.get(query_key, {
            'cwe': query_key.split('_')[0], 'query': '_'.join(query_key.split('_')[1:]),
            'tp': 0, 'fp': 0, 'total': 0, 'tp_rate': 0.0
        })
        
        aligned_initial.append(initial_data)
        aligned_final.append(final_data)
    
    # Sort by total increase (final total - initial total) for better visualization
    total_increases = [f['total'] - i['total'] for i, f in zip(aligned_initial, aligned_final)]
    sorted_indices = sorted(range(len(total_increases)), 
                           key=lambda i: total_increases[i], reverse=True)
    
    aligned_initial = [aligned_initial[i] for i in sorted_indices]
    aligned_final = [aligned_final[i] for i in sorted_indices]
    
    # Create figure with grouped bar chart
    fig, ax = plt.subplots(figsize=(20, 10))
    
    # Prepare data
    labels = [f"CWE-{r['cwe']}\n{r['query']}" for r in aligned_final]
    
    initial_tp = [r['tp'] for r in aligned_initial]
    initial_fp = [r['fp'] for r in aligned_initial]
    initial_total = [r['total'] for r in aligned_initial]
    
    final_tp = [r['tp'] for r in aligned_final]
    final_fp = [r['fp'] for r in aligned_final]
    final_total = [r['total'] for r in aligned_final]
    
    x = np.arange(len(labels))
    width = 0.35
    
    # Calculate max height for scaling
    max_height = max(max(initial_total + final_total), 1)
    
    # Create stacked bars - Initial on left, Final on right
    # Initial results (with diagonal hatching)
    for i in range(len(labels)):
        # Make bars visible even for 0 values
        display_total = max(initial_total[i], max_height * 0.005) if initial_total[i] == 0 else initial_total[i]
        
        if initial_total[i] > 0:
            # Stack: True Positives (red) at bottom, False Positives (yellow) on top
            # True Positives
            ax.bar(x[i] - width/2, initial_tp[i], width,
                   color='#DC143C', alpha=0.8, edgecolor='black', linewidth=1.5,
                   hatch='///', label='True Positives' if i == 0 else "")
            # False Positives
            ax.bar(x[i] - width/2, initial_fp[i], width, bottom=initial_tp[i],
                   color='#4169E1', alpha=0.8, edgecolor='black', linewidth=1.5,
                   hatch='///', label='False Positives' if i == 0 else "")
        else:
            # Empty bar with initial hatching
            ax.bar(x[i] - width/2, display_total, width,
                   color='lightgray', alpha=0.3, edgecolor='black', linewidth=1.5,
                   hatch='///')
    
    # Final results (with dot hatching)
    for i in range(len(labels)):
        # Make bars visible even for 0 values
        display_total = max(final_total[i], max_height * 0.005) if final_total[i] == 0 else final_total[i]
        
        if final_total[i] > 0:
            # Stack: True Positives (red) at bottom, False Positives (yellow) on top
            # True Positives
            ax.bar(x[i] + width/2, final_tp[i], width,
                   color='#DC143C', alpha=0.8, edgecolor='black', linewidth=1.5,
                   hatch='...')
            # False Positives
            ax.bar(x[i] + width/2, final_fp[i], width, bottom=final_tp[i],
                   color='#4169E1', alpha=0.8, edgecolor='black', linewidth=1.5,
                   hatch='...')
        else:
            # Empty bar with final hatching
            ax.bar(x[i] + width/2, display_total, width,
                   color='lightgray', alpha=0.3, edgecolor='black', linewidth=1.5,
                   hatch='...')
    
    # Add custom legend
    from matplotlib.patches import Patch, Rectangle
    from matplotlib.lines import Line2D
    
    # Create custom legend elements
    legend_elements = [
        # Result types
        Rectangle((0,0), 1, 1, facecolor='#DC143C', alpha=0.8, edgecolor='black', linewidth=1, label='True Positives'),
        Rectangle((0,0), 1, 1, facecolor='#4169E1', alpha=0.8, edgecolor='black', linewidth=1, label='False Positives'),
        # Separator
        Line2D([0], [0], color='none', label=''),
        # Pattern types
        Rectangle((0,0), 1, 1, facecolor='gray', alpha=0.5, edgecolor='black', linewidth=1.5, 
                 hatch='///', label='Initial Results'),
        Rectangle((0,0), 1, 1, facecolor='gray', alpha=0.5, edgecolor='black', linewidth=1.5, 
                 hatch='...', label='Final Results'),
    ]
    ax.legend(handles=legend_elements, loc='upper right', fontsize=11, framealpha=0.9)
    
    ax.set_xlabel('CWE and Query', fontsize=14, fontweight='bold')
    ax.set_ylabel('Number of Results', fontsize=14, fontweight='bold')
    ax.set_title('CodeQL Query Results: Before vs After Optimization\n(Sorted by Total Result Increase)', 
                 fontsize=16, fontweight='bold')
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=45, ha='right', fontsize=10)
    ax.grid(True, alpha=0.3, axis='y')
    
    # Add value labels and increase indicators
    for i in range(len(labels)):
        # Initial bar labels
        if initial_total[i] > 0:
            # Show total on top
            ax.text(x[i] - width/2, initial_total[i] + max_height * 0.01, 
                   str(initial_total[i]), ha='center', va='bottom', fontsize=7, fontweight='bold')
            # Show TP count in red section if significant
            if initial_tp[i] > initial_total[i] * 0.15:
                ax.text(x[i] - width/2, initial_tp[i]/2, str(initial_tp[i]), 
                       ha='center', va='center', color='white', fontsize=6, fontweight='bold')
            # Show FP count in blue section if significant
            if initial_fp[i] > initial_total[i] * 0.15:
                ax.text(x[i] - width/2, initial_tp[i] + initial_fp[i]/2, str(initial_fp[i]), 
                       ha='center', va='center', color='white', fontsize=6, fontweight='bold')
        else:
            ax.text(x[i] - width/2, max_height * 0.01, '0', 
                   ha='center', va='bottom', fontsize=7, fontweight='bold')
        
        # Final bar labels
        if final_total[i] > 0:
            # Show total on top
            ax.text(x[i] + width/2, final_total[i] + max_height * 0.01, 
                   str(final_total[i]), ha='center', va='bottom', fontsize=7, fontweight='bold')
            # Show TP count in red section if significant
            if final_tp[i] > final_total[i] * 0.15:
                ax.text(x[i] + width/2, final_tp[i]/2, str(final_tp[i]), 
                       ha='center', va='center', color='white', fontsize=6, fontweight='bold')
            # Show FP count in blue section if significant
            if final_fp[i] > final_total[i] * 0.15:
                ax.text(x[i] + width/2, final_tp[i] + final_fp[i]/2, str(final_fp[i]), 
                       ha='center', va='center', color='white', fontsize=6, fontweight='bold')
        else:
            ax.text(x[i] + width/2, max_height * 0.01, '0', 
                   ha='center', va='bottom', fontsize=7, fontweight='bold')
        
        # Add increase indicator
        increase = final_total[i] - initial_total[i]
        if increase > 0:
            # Draw arrow and show increase
            arrow_y = max(initial_total[i], final_total[i]) + max_height * 0.05
            ax.annotate(f'+{increase}', xy=(x[i], arrow_y), 
                       ha='center', va='bottom', fontsize=8, 
                       color='darkgreen', fontweight='bold',
                       bbox=dict(boxstyle="round,pad=0.3", facecolor='lightgreen', alpha=0.7))
        
    
    # Calculate and display summary statistics
    initial_total_tp = sum(initial_tp)
    initial_total_fp = sum(initial_fp)
    initial_total_all = sum(initial_total)
    
    final_total_tp = sum(final_tp)
    final_total_fp = sum(final_fp)
    final_total_all = sum(final_total)
    
    # Calculate average TP rates
    initial_tp_rates = [r['tp_rate'] for r in aligned_initial]
    final_tp_rates = [r['tp_rate'] for r in aligned_final]
    initial_avg_tp_rate = np.mean([r for r in initial_tp_rates if r > 0]) if any(r > 0 for r in initial_tp_rates) else 0
    final_avg_tp_rate = np.mean([r for r in final_tp_rates if r > 0]) if any(r > 0 for r in final_tp_rates) else 0
    
    # Add statistics text box
    stats_text = f"""Summary Statistics:
Initial: {initial_total_all:,} results ({initial_total_tp:,} TP, {initial_total_fp:,} FP) - Avg TP Rate: {initial_avg_tp_rate:.1f}%
Final: {final_total_all:,} results ({final_total_tp:,} TP, {final_total_fp:,} FP) - Avg TP Rate: {final_avg_tp_rate:.1f}%
Improvement: {final_total_all - initial_total_all:+,} results ({final_total_tp - initial_total_tp:+,} TP)"""
    
    ax.text(0.02, 0.98, stats_text, transform=ax.transAxes, fontsize=11,
             verticalalignment='top', 
             bbox=dict(boxstyle='round,pad=0.5', facecolor='lightyellow', alpha=0.8))
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    print(f"Initial vs Final comparison chart saved to: {output_path}")
    plt.show()

def create_tp_rate_comparison(initial_results, final_results, output_path):
    """Create TP rate comparison chart."""
    # Align data similar to above
    all_queries = set()
    initial_dict = {f"{r['cwe']}_{r['query']}": r for r in initial_results}
    final_dict = {f"{r['cwe']}_{r['query']}": r for r in final_results}
    all_queries = set(initial_dict.keys()) | set(final_dict.keys())
    
    aligned_initial = []
    aligned_final = []
    
    for query_key in sorted(all_queries):
        initial_data = initial_dict.get(query_key, {
            'cwe': query_key.split('_')[0], 'query': '_'.join(query_key.split('_')[1:]),
            'tp_rate': 0.0
        })
        final_data = final_dict.get(query_key, {
            'cwe': query_key.split('_')[0], 'query': '_'.join(query_key.split('_')[1:]),
            'tp_rate': 0.0
        })
        
        aligned_initial.append(initial_data)
        aligned_final.append(final_data)
    
    # Sort by improvement (final - initial)
    improvements = [f['tp_rate'] - i['tp_rate'] for i, f in zip(aligned_initial, aligned_final)]
    sorted_indices = sorted(range(len(improvements)), key=lambda i: improvements[i], reverse=True)
    
    aligned_initial = [aligned_initial[i] for i in sorted_indices]
    aligned_final = [aligned_final[i] for i in sorted_indices]
    improvements = [improvements[i] for i in sorted_indices]
    
    # Create the TP rate comparison chart
    fig, ax = plt.subplots(figsize=(20, 8))
    
    labels = [f"CWE-{r['cwe']}\n{r['query']}" for r in aligned_final]
    initial_rates = [r['tp_rate'] for r in aligned_initial]
    final_rates = [r['tp_rate'] for r in aligned_final]
    
    x = np.arange(len(labels))
    width = 0.35
    
    bars1 = ax.bar(x - width/2, initial_rates, width, label='Initial TP Rate', 
                   color='#FF6B6B', alpha=0.8)
    bars2 = ax.bar(x + width/2, final_rates, width, label='Final TP Rate', 
                   color='#4ECDC4', alpha=0.8)
    
    # Add improvement arrows
    for i, (init_rate, final_rate, improvement) in enumerate(zip(initial_rates, final_rates, improvements)):
        if abs(improvement) > 1:  # Only show significant improvements
            arrow_color = 'green' if improvement > 0 else 'red'
            arrow_style = '↑' if improvement > 0 else '↓'
            ax.annotate(f'{arrow_style}{abs(improvement):.1f}%', 
                       xy=(i, max(init_rate, final_rate) + 2),
                       ha='center', va='bottom', color=arrow_color, fontweight='bold', fontsize=8)
    
    ax.set_xlabel('CWE and Query', fontsize=12, fontweight='bold')
    ax.set_ylabel('True Positive Rate (%)', fontsize=12, fontweight='bold')
    ax.set_title('True Positive Rate Comparison: Initial vs Final\n(Sorted by Improvement)', 
                 fontsize=14, fontweight='bold')
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=45, ha='right', fontsize=9)
    ax.legend()
    ax.grid(True, alpha=0.3, axis='y')
    ax.set_ylim(0, 105)
    
    # Add value labels on bars
    for bar in bars1:
        height = bar.get_height()
        if height > 0:
            ax.text(bar.get_x() + bar.get_width()/2., height + 0.5,
                   f'{height:.1f}%', ha='center', va='bottom', fontsize=8)
    
    for bar in bars2:
        height = bar.get_height()
        if height > 0:
            ax.text(bar.get_x() + bar.get_width()/2., height + 0.5,
                   f'{height:.1f}%', ha='center', va='bottom', fontsize=8)
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    print(f"TP Rate comparison chart saved to: {output_path}")
    plt.show()

def print_comparison_table(initial_results, final_results):
    """Print comparison table."""
    # Align data
    all_queries = set()
    initial_dict = {f"{r['cwe']}_{r['query']}": r for r in initial_results}
    final_dict = {f"{r['cwe']}_{r['query']}": r for r in final_results}
    all_queries = set(initial_dict.keys()) | set(final_dict.keys())
    
    comparisons = []
    for query_key in sorted(all_queries):
        initial_data = initial_dict.get(query_key, {
            'cwe': query_key.split('_')[0], 'query': '_'.join(query_key.split('_')[1:]),
            'tp': 0, 'fp': 0, 'total': 0, 'tp_rate': 0.0
        })
        final_data = final_dict.get(query_key, {
            'cwe': query_key.split('_')[0], 'query': '_'.join(query_key.split('_')[1:]),
            'tp': 0, 'fp': 0, 'total': 0, 'tp_rate': 0.0
        })
        
        comparisons.append({
            'cwe': final_data['cwe'],
            'query': final_data['query'],
            'initial_tp': initial_data['tp'],
            'initial_fp': initial_data['fp'],
            'initial_total': initial_data['total'],
            'initial_tp_rate': initial_data['tp_rate'],
            'final_tp': final_data['tp'],
            'final_fp': final_data['fp'],
            'final_total': final_data['total'],
            'final_tp_rate': final_data['tp_rate'],
            'tp_improvement': final_data['tp'] - initial_data['tp'],
            'total_improvement': final_data['total'] - initial_data['total'],
            'tp_rate_improvement': final_data['tp_rate'] - initial_data['tp_rate']
        })
    
    # Sort by TP rate improvement
    comparisons.sort(key=lambda x: x['tp_rate_improvement'], reverse=True)
    
    print(f"\n{'='*150}")
    print(f"{'INITIAL vs FINAL COMPARISON':^150}")
    print(f"{'='*150}")
    print(f"{'CWE':<6} {'Query':<30} {'Initial':<25} {'Final':<25} {'Improvement':<25} {'TP Rate Δ'}")
    print(f"{'':<6} {'':<30} {'TP/FP/Total':<25} {'TP/FP/Total':<25} {'TP/Total':<25} {'(%)':>10}")
    print(f"{'-'*150}")
    
    for c in comparisons:
        initial_str = f"{c['initial_tp']}/{c['initial_fp']}/{c['initial_total']}"
        final_str = f"{c['final_tp']}/{c['final_fp']}/{c['final_total']}"
        improvement_str = f"{c['tp_improvement']:+}/{c['total_improvement']:+}"
        
        print(f"CWE-{c['cwe']:<3} {c['query']:<30} {initial_str:<25} {final_str:<25} {improvement_str:<25} {c['tp_rate_improvement']:+7.1f}%")

def main():
    parser = argparse.ArgumentParser(description='Generate initial vs final comparison charts')
    parser.add_argument('--workspace', type=str, default='/hdd2/QL-Relax/qlworkspace',
                        help='Path to QL-Relax workspace directory')
    parser.add_argument('--output-dir', type=str, default='/hdd2/QL-Relax',
                        help='Output directory for charts')
    
    args = parser.parse_args()
    
    print("Collecting initial and final results...")
    initial_results, final_results = collect_initial_and_final_results(args.workspace)
    
    if not initial_results and not final_results:
        print("No results found!")
        return
    
    print(f"Found {len(initial_results)} initial results and {len(final_results)} final results")
    
    # Print comparison table
    print_comparison_table(initial_results, final_results)
    
    # Generate comparison charts
    print("\nGenerating initial vs final comparison chart...")
    comparison_path = os.path.join(args.output_dir, 'initial_vs_final_comparison.png')
    create_comparison_chart(initial_results, final_results, comparison_path)
    
    print("Generating TP rate comparison chart...")
    tp_rate_path = os.path.join(args.output_dir, 'tp_rate_comparison.png')
    create_tp_rate_comparison(initial_results, final_results, tp_rate_path)

if __name__ == "__main__":
    main()