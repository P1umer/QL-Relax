"""
QL Query Modification Configuration
Defines the state machine for modifying QL queries based on iteration context:
- First iteration: Broaden to capture more results
- Compile error: Fix compilation errors
- Result decrease: Try different broadening strategy
"""

from BaseMachine.agent_action_utils import create_agent_action
import os
import json
from QLWorkflow.util.logging_utils import get_ql_workflow_log_path, get_action_type_from_prompt

# Get the directory of the script for relative paths
SCRIPT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def get_cwe_specific_strategies(cwe_number):
    """Get CWE-specific strategies for removing limitations that cause False Negatives."""
    strategies = {
        22: {  # Path Traversal
            "broadening": [
                "**Remove Source Limitations**: Add environment variables, config files, command args beyond just direct user input",
                "**Remove Sink Limitations**: Add fopen, access, stat, readlink beyond just open() calls",
                "**Remove Sanitizer Over-restriction**: Relax path validation checks that block legitimate traversal detection",
                "**Remove Flow Limitations**: Add flow through path manipulation functions like realpath, dirname, basename",
                "**Remove Pattern Limitations**: Add '.\\\\', URL encoding (%2e%2e), double encoding beyond just '../'",
                "**Remove Scope Limitations**: Remove artificial directory boundaries and path restrictions"
            ],
            "recovery": [
                "Remove ALL path validation barriers to find what's being missed",
                "Expand file operation sinks to include ANY filesystem interaction",
                "Track paths through ALL intermediate variables and functions",
                "Include path usage in logging, config, and utility functions",
                "Add ALL encoding variations of path traversal patterns",
                "Remove ANY directory or path scope restrictions"
            ]
        },
        23: {  # Relative Path Traversal
            "broadening": [
                "**Remove Source Limitations**: Add environment vars, config files, web params beyond direct argv/stdin",
                "**Remove Sink Limitations**: Add access, stat, chmod, unlink operations beyond fopen/open",
                "**Remove Sanitizer Over-restriction**: Relax validation to detect './../../' and other relative patterns",
                "**Remove Flow Limitations**: Add string builder tracking to not lose track through concatenation",
                "**Remove Pattern Limitations**: Add './', mixed separators, encoded patterns beyond just '../'",
                "**Remove Context Limitations**: Add paths in exec commands, URLs beyond just file contexts"
            ],
            "recovery": [
                "Remove ALL relative path validation to expose gaps",
                "Track ANY string that reaches file operations",
                "Include path usage in secondary contexts (logging, temp files)",
                "Add ALL path normalization bypasses",
                "Track paths through ALL string operations",
                "Remove restrictions on 'safe' directories"
            ]
        },
        36: {  # Absolute Path Traversal
            "broadening": [
                "**Remove Source Limitations**: Add hidden sources like headers, cookies beyond obvious inputs",
                "**Remove Sink Limitations**: Add dynamic loading operations, includes/requires beyond basic file ops",
                "**Remove Sanitizer Over-restriction**: Relax whitelist validation to detect bypass attempts",
                "**Remove Flow Limitations**: Track through os.path.join, Path operations where query currently stops",
                "**Remove Pattern Limitations**: Add Windows paths, UNC paths, file:// URLs beyond Unix paths",
                "**Remove Validation Limitations**: Add symlink/hardlink bypasses to defeat path.startswith checks"
            ],
            "recovery": [
                "Remove ALL absolute path restrictions",
                "Track paths to ANY system resource access",
                "Include path resolution bypasses (symlinks, .., //)",
                "Add paths used in dynamic code loading",
                "Track through ALL path transformation functions",
                "Remove OS-specific path assumptions"
            ]
        },
        78: {  # OS Command Injection
            "broadening": [
                "**Remove Source Limitations**: Add environment vars, config files, network inputs, file contents beyond argv/stdin",
                "**Remove Sink Limitations**: Add system, popen, execve, spawn*, CreateProcess, shell scripts beyond basic exec",
                "**Remove Sanitizer Over-restriction**: Relax command validation to detect injection through 'safe' commands",
                "**Remove Flow Limitations**: Add concatenation, formatting, shell escaping tracking to not lose data flow",
                "**Remove Pattern Limitations**: Add &&, ||, `, $(), backticks, newlines beyond just ';' and '|'",
                "**Remove Context Limitations**: Track injection into ANY part of command string, not just the command name"
            ],
            "recovery": [
                "Remove ALL command validation to expose False Negatives",
                "Track ANY string that reaches ANY process execution function",
                "Include command execution through interpreters (sh -c, cmd /c, eval)",
                "Track commands built through multiple string operations",
                "Add ALL shell metacharacters and encoding variations",
                "Remove restrictions on 'safe' commands or whitelists"
            ]
        },
        114: {  # Uncontrolled Process Operation
            "broadening": [
                "**Remove Source Limitations**: Add process names, paths, command args beyond just PID from user",
                "**Remove Sink Limitations**: Add ptrace, setpriority, nice, taskset beyond just kill()",
                "**Remove Sanitizer Over-restriction**: Relax PID validation to detect negative PIDs, special values",
                "**Remove Flow Limitations**: Add container tracking to not lose PIDs in data structures",
                "**Remove Pattern Limitations**: Add signal handlers, IPC operations for indirect process control",
                "**Remove Permission Limitations**: Remove privilege check assumptions to find privilege escalation"
            ],
            "recovery": [
                "Remove ALL process ID validation",
                "Track ANY value reaching process operations",
                "Include process control through /proc filesystem",
                "Add process manipulation via debugging interfaces",
                "Track PIDs through ALL storage (files, memory, IPC)",
                "Remove ALL permission and capability checks"
            ]
        },
        134: {  # Uncontrolled Format String
            "broadening": [
                "**Remove Source Limitations**: Track format strings in ANY position, not just first printf arg",
                "**Remove Sink Limitations**: Add snprintf, vsprintf, asprintf, dprintf beyond basic printf/sprintf",
                "**Remove Type Limitations**: Relax to include char*, void*, implicit conversions beyond exact string type",
                "**Remove Flow Limitations**: Track formats through returns, out params beyond function boundaries",
                "**Remove Pattern Limitations**: Add %s crashes, info leaks via %x, %p beyond just %n",
                "**Remove Context Limitations**: Add logging libs, debug functions beyond standard format functions"
            ],
            "recovery": [
                "Remove ALL format string type checking",
                "Track ANY data reaching format positions",
                "Include ALL printf-family functions and wrappers",
                "Add format strings in error handlers and assertions",
                "Track formats through global variables and heap",
                "Remove compile-time format checking assumptions"
            ]
        },
        190: {  # Integer Overflow
            "broadening": [
                "**Remove Source Limitations**: Add lengths, sizes, counts from files/network beyond just user input",
                "**Remove Sink Limitations**: Add array indexes, loop bounds, offsets beyond just malloc size",
                "**Remove Operation Limitations**: Add addition chains, bit shifts beyond just multiplication",
                "**Remove Type Limitations**: Add implicit conversions, casts to catch signed/unsigned mixing",
                "**Remove Flow Limitations**: Track through multiple arithmetic steps for compound operations",
                "**Remove Context Limitations**: Add if/while/for expressions to catch overflows in conditions"
            ],
            "recovery": [
                "Remove ALL integer bounds validation",
                "Track ALL arithmetic operations on integers",
                "Include integer promotions and implicit casts",
                "Add overflows in width/height/size calculations",
                "Track through complex expressions and macros",
                "Remove assumptions about integer sizes"
            ]
        },
        191: {  # Integer Underflow
            "broadening": [
                "**Remove Source Limitations**: Add decrement, negative addition beyond direct subtraction",
                "**Remove Sink Limitations**: Add buffer sizes, loop counters, offsets to catch underflow effects",
                "**Remove Operation Limitations**: Add complex expressions, ternary ops beyond basic subtraction",
                "**Remove Type Limitations**: Track unsigned arithmetic explicitly to catch unsigned wrap",
                "**Remove Flow Limitations**: Track through variable updates, returns beyond assignments",
                "**Remove Boundary Limitations**: Add underflow from positive values, not just assuming 0 boundary"
            ],
            "recovery": [
                "Remove ALL minimum value checks",
                "Track ALL subtraction and decrement operations",
                "Include underflow in size/length calculations",
                "Add underflows causing negative array indexes",
                "Track through pointer arithmetic",
                "Remove assumptions about unsigned behavior"
            ]
        },
        319: {  # Cleartext Transmission
            "broadening": [
                "**Remove Source Limitations**: Add tokens, keys, PII, session IDs beyond just passwords",
                "**Remove Sink Limitations**: Add HTTP, files, logs, databases beyond socket send",
                "**Remove Encryption Limitations**: Relax to detect weak/broken crypto, not just missing crypto",
                "**Remove Flow Limitations**: Track through JSON, XML, encoding to not lose data in serialization",
                "**Remove Pattern Limitations**: Add proprietary, IoT, embedded comms beyond standard protocols",
                "**Remove Context Limitations**: Add logging, trace, dump functions beyond production code"
            ],
            "recovery": [
                "Remove ALL encryption requirements",
                "Track ANY sensitive data to ANY output",
                "Include cleartext in error messages and logs",
                "Add transmission via side channels (DNS, ICMP)",
                "Track through encoding but not encryption",
                "Remove distinctions between prod and debug code"
            ]
        },
        416: {  # Use After Free
            "broadening": [
                "**Remove Source Limitations**: Add new/delete, alloca, custom allocators beyond malloc/free",
                "**Remove Sink Limitations**: Add member access, virtual calls, callbacks beyond direct deref",
                "**Remove Temporal Limitations**: Track delayed use through event loops, not just immediate use",
                "**Remove Aliasing Limitations**: Track through assignments, containers to catch pointer copies",
                "**Remove Scope Limitations**: Track heap pointers globally beyond function scope",
                "**Remove Pattern Limitations**: Add multiple frees, destructor issues beyond single free"
            ],
            "recovery": [
                "Remove ALL lifetime analysis",
                "Track ALL pointers after ANY free operation",
                "Include use through aliased pointers",
                "Add UAF in cleanup/error handlers",
                "Track through function pointers and vtables",
                "Remove assumptions about memory manager"
            ]
        },
        789: {  # Memory Allocation with Excessive Size
            "broadening": [
                "**Remove Source Limitations**: Add calculated sizes, multiplied values beyond direct size",
                "**Remove Sink Limitations**: Add calloc, realloc, new[], VLAs, alloca beyond malloc",
                "**Remove Calculation Limitations**: Track arithmetic on sizes to catch integer overflow",
                "**Remove Unit Limitations**: Add element counts, structure sizes beyond assuming bytes",
                "**Remove Flow Limitations**: Track through parameters, returns to not lose sizes in functions",
                "**Remove Context Limitations**: Add cumulative allocation patterns in loops"
            ],
            "recovery": [
                "Remove ALL size validation completely",
                "Track ANY numeric value to allocation functions",
                "Include sizes from untrusted sources",
                "Add allocation in loops without bounds",
                "Track through size calculation chains",
                "Remove platform memory limit assumptions"
            ]
        },
        843: {  # Type Confusion
            "broadening": [
                "**Remove Source Limitations**: Add reinterpret_cast, unions, void* beyond C-style casts",
                "**Remove Sink Limitations**: Add member access, RTTI, dynamic_cast beyond vtable calls",
                "**Remove Hierarchy Limitations**: Add multiple, virtual inheritance beyond single inheritance",
                "**Remove Safety Limitations**: Remove trust in dynamic_cast to find failed cast handling",
                "**Remove Container Limitations**: Add STL, generics to catch type confusion in templates",
                "**Remove Lifetime Limitations**: Add reuse after destruction for temporal type changes"
            ],
            "recovery": [
                "Remove ALL type compatibility checking",
                "Track ALL pointer casts and conversions",
                "Include type confusion through unions",
                "Add confusion in template instantiations",
                "Track through inheritance hierarchies",
                "Remove RTTI and safe casting assumptions"
            ]
        }
    }
    
    # Default strategy for unknown CWEs
    default_strategy = {
        "broadening": [
            "**Remove Source Limitations**: Expand to all untrusted sources beyond narrow input definition",
            "**Remove Sink Limitations**: Add all potentially dangerous operations beyond current sinks",
            "**Remove Sanitizer Over-restriction**: Relax validation to find real vulnerabilities",
            "**Remove Flow Limitations**: Improve flow through all transformations to not lose data",
            "**Remove Pattern Limitations**: Add variations and encodings beyond specific patterns",
            "**Remove Scope Limitations**: Broaden scope to find all instances beyond current focus"
        ],
        "recovery": [
            "Remove ALL validation and sanitization barriers",
            "Track data to ALL possible sinks",
            "Include ALL indirect patterns",
            "Add ALL encoding and obfuscation variants",
            "Remove ALL safety assumptions",
            "Expand to widest possible vulnerability definition"
        ]
    }
    
    return strategies.get(cwe_number, default_strategy)


def modify_ql_query_action(machine):
    """
    Action to modify QL query based on the iteration context:
    - First iteration: Broaden constraints to capture more results
    - Compile error: Fix the compilation errors
    - Result decrease: Broaden constraints with warning about decrease
    """
    print(f"\n[QL Query Modification] Starting iteration {machine.context.current_iteration} for CWE-{machine.context.cwe_number}")
    
    # Determine the modification type based on previous results
    modification_type = "broaden"  # default for first iteration
    extra_context = ""
    
    # Add previous iteration context if not the first iteration
    if machine.context.current_iteration > 1:
        # Build paths to previous iteration's files
        prev_iteration = machine.context.current_iteration - 1
        prev_iteration_dir = os.path.join(machine.context.output_dir, f"iteration_{prev_iteration}")
        prev_ql_path = os.path.join(prev_iteration_dir, "query_results", os.path.basename(machine.context.ql_file_path))
        prev_validation_path = os.path.join(prev_iteration_dir, "validation_conclusion.json")
        
        extra_context = f"\n\nPREVIOUS ITERATION CONTEXT:"
        extra_context += f"\nPrevious Modified QL: {prev_ql_path}"
        extra_context += f"\nPrevious Validation Conclusion: {prev_validation_path}"
        extra_context += "\n\nPlease read the previous validation conclusion to understand what needs improvement."
    
    if machine.context.previous_results:
        last_result = machine.context.previous_results
        if isinstance(last_result, dict):
            # Check for compile error
            if last_result.get('compile_error'):
                modification_type = "fix_compile_error"
                extra_context += f"\n\nPREVIOUS COMPILATION ERROR:\n{last_result.get('error_message', '')}\n\nYou MUST fix this compilation error."
            # Check for result decrease
            elif last_result.get('result_decreased'):
                modification_type = "broaden_with_warning"
                extra_context += f"\n\nWARNING: The previous modification resulted in FEWER results ({last_result.get('previous_count', 0)} -> {last_result.get('current_count', 0)}).\nThis approach seems to be reducing results instead of increasing them. Please try a different broadening strategy."
    
    # Read library paths from previous iteration if available
    library_paths_info = ""
    if machine.context.current_iteration > 1:
        prev_iteration = machine.context.current_iteration - 1
        prev_iteration_dir = os.path.join(machine.context.output_dir, f"iteration_{prev_iteration}")
        library_paths_file = os.path.join(prev_iteration_dir, "query_results", "library_paths.json")
        if os.path.exists(library_paths_file):
            with open(library_paths_file, 'r') as f:
                library_paths = json.load(f)
                if library_paths:
                    library_paths_info = f"\n\nPREVIOUS LIBRARY MODIFICATIONS:\n"
                    for lib_info in library_paths:
                        library_paths_info += f"- Original: {lib_info['original_path']}\n"
                        library_paths_info += f"  Modified: {lib_info['modified_path']}\n"
    
    # Get CWE-specific strategies
    cwe_strategies = get_cwe_specific_strategies(machine.context.cwe_number)
    broadening_strategies = "\n".join([f"{i+1}. {strategy}" for i, strategy in enumerate(cwe_strategies["broadening"])])
    recovery_strategies = "\n".join([f"- {strategy}" for strategy in cwe_strategies["recovery"]])
    
    # Get the base filename without extension for dynamic file naming
    ql_base_name = os.path.splitext(os.path.basename(machine.context.ql_file_path))[0]
    
    # Construct the prompt based on modification type
    if modification_type == "fix_compile_error":
        prompt_template = """You are a CodeQL expert. The following QL query has compilation errors that need to be fixed.

CWE Number: {cwe_number}
{extra_context}{library_paths_info}

MANDATORY VERIFICATION WORKFLOW:
You MUST follow this EXACT process and NOT stop until BOTH conditions are satisfied:

STEP 1: Get Origin Result Count
First, check the origin result count by examining the CSV file:
```bash
wc -l {query_origin_dir}/*.csv
```
Note: Subtract 1 from the line count to get actual results (excluding header).
RECORD THIS NUMBER - you must beat it!

STEP 2: Fix Query and Test Loop
1. The input query has been copied to: {codeql_dir}/{ql_base_name}_modified.ql
2. If this is not the first iteration, read the previous validation conclusion
3. Read and modify the query at: {codeql_dir}/{ql_base_name}_modified.ql
4. Fix compilation errors and broaden the query in-place
5. Test compilation and execution (use tmp directory for output to avoid overwriting the original query):
```bash
python3 {run_juliet_path} --run-queries --cwe {cwe_number} --ql {codeql_dir}/{ql_base_name}_modified.ql --output .tmp/ql_test_{cwe_number}
```
6. If compilation fails, go back to step 3
7. If compilation succeeds, check result count:
```bash
wc -l .tmp/ql_test_{cwe_number}/*.csv
```
9. Compare: If new result count <= origin count, go back to step 3 with MORE aggressive broadening
10. Only stop when: COMPILATION SUCCESS AND NEW_COUNT > ORIGIN_COUNT

CRITICAL SUCCESS CRITERIA:
[REQUIRED] Query compiles without errors
[REQUIRED] Result count is GREATER than origin (not equal!)

MANDATORY VERIFICATION COMMANDS:
Before declaring success, you MUST run these verification commands:
```bash
# Check origin count
wc -l {query_origin_dir}/*.csv
# Check new count  
wc -l .tmp/ql_test_{cwe_number}/*.csv
# Confirm new > origin
```

FAILURE RECOVERY STRATEGIES:
If result count doesn't increase after multiple attempts:
{recovery_strategies}


LIBRARY MODIFICATION GUIDELINES:
When you need to modify QL library files:
1. DO NOT modify the original library file directly
2. Create a copy of the library file in the same directory with '_modified' suffix
   Example: DataFlow.qll -> DataFlow_modified.qll
3. Update the import statement in your query to use the modified library
   Example: import DataFlow -> import DataFlow_modified
4. Track all library modifications in a JSON file at:
   .tmp/library_paths.json
   Format: [{{"original_path": "...", "modified_path": "..."}}]
5. If modifying multiple libraries, ensure they import each other correctly
6. Common library files that can be modified:
   - Data flow configuration files
   - Source/sink definition files
   - Taint tracking configuration files
7. Document changes clearly in the modified library file

You are NOT done until you achieve MORE results than origin while maintaining compilation success!"""
    else:
        # Both "broaden" and "broaden_with_warning" use similar prompts
        prompt_template = """You are a CodeQL expert tasked with identifying and removing limitations in QL queries that cause False Negatives (missing real vulnerabilities).

CWE Number: {cwe_number}
{extra_context}{library_paths_info}

YOUR PRIMARY GOAL: Identify query limitations causing False Negatives and systematically remove them.

MANDATORY VERIFICATION WORKFLOW:
You MUST follow this EXACT process and NOT stop until BOTH conditions are satisfied:

STEP 1: Understand Current Limitations
1. Check the origin result count:
```bash
wc -l {query_origin_dir}/*.csv
```
Note: Subtract 1 from the line count to get actual results (excluding header).
RECORD THIS NUMBER - you must beat it!

2. Read the query at: {codeql_dir}/{ql_base_name}_modified.ql
3. Identify limitations that might cause False Negatives:
   - Overly restrictive source definitions
   - Missing sink patterns
   - Too strict sanitizer/barrier conditions
   - Limited data flow configurations
   - Narrow predicate definitions

STEP 2: Remove Limitations and Test
1. If this is not the first iteration, read the previous validation conclusion
2. Systematically remove identified limitations in the query
3. Test compilation and execution:
```bash
python3 {run_juliet_path} --run-queries --cwe {cwe_number} --ql {codeql_dir}/{ql_base_name}_modified.ql --output .tmp/ql_test_{cwe_number}
```
4. If compilation fails, fix errors while preserving the limitation removals
5. Check new result count:
```bash
wc -l .tmp/ql_test_{cwe_number}/*.csv
```
6. If new count <= origin, identify MORE limitations to remove
7. Only stop when: COMPILATION SUCCESS AND NEW_COUNT > ORIGIN_COUNT

CRITICAL SUCCESS CRITERIA:
[REQUIRED] Query compiles without errors
[REQUIRED] Result count is GREATER than origin (not equal!)

MANDATORY VERIFICATION COMMANDS:
Before declaring success, you MUST run these verification commands:
```bash
# Check origin count
wc -l {query_origin_dir}/*.csv
# Check new count  
wc -l .tmp/ql_test_{cwe_number}/*.csv
# Confirm new > origin
```

LIMITATION REMOVAL STRATEGIES (systematic approaches):
{broadening_strategies}

AGGRESSIVE LIMITATION REMOVAL (if initial attempts fail):
If result count doesn't increase after multiple attempts:
{recovery_strategies}

LIBRARY MODIFICATION GUIDELINES:
When you need to modify QL library files:
1. DO NOT modify the original library file directly
2. Create a copy of the library file in the same directory with '_modified' suffix
   Example: DataFlow.qll -> DataFlow_modified.qll
3. Update the import statement in your query to use the modified library
   Example: import DataFlow -> import DataFlow_modified
4. Track all library modifications in a JSON file at:
   .tmp/library_paths.json
   Format: [{{"original_path": "...", "modified_path": "...", "import_change": "..."}}]
5. If modifying multiple libraries, ensure they import each other correctly
6. Common library files that can be modified:
   - Data flow configuration files (e.g., DataFlow.qll, TaintTracking.qll)
   - Source/sink definition files
   - Custom library files specific to the CWE
   - Helper predicates and utility libraries
7. Use the Read tool to examine library imports and Write/Edit tools to create modified versions
8. Document changes clearly in the modified library file

VERIFICATION REQUIREMENT:
You are NOT done until you achieve MORE results than origin while maintaining compilation success!
Show me the exact counts in your final verification step."""
    
    # Set up logging context for QLWorkflow
    log_context = {
        'cwe_number': machine.context.cwe_number,
        'query_name': machine.context.query_name if hasattr(machine.context, 'query_name') else f"CWE-{machine.context.cwe_number:03d}",
        'iteration': machine.context.current_iteration,
        'output_dir': machine.context.output_dir
    }
    
    # Get the log path and action type
    log_path = get_ql_workflow_log_path(log_context)
    if log_path:
        machine.context.session_log_path = str(log_path)  # Convert Path to string
    
    # Determine action type from prompt
    run_juliet_path = os.path.join(SCRIPT_DIR, 'run_juliet.py')
    formatted_prompt_preview = prompt_template.format(
        cwe_number=machine.context.cwe_number,
        extra_context="",
        library_paths_info="",
        broadening_strategies="",
        recovery_strategies="",
        query_origin_dir="",
        codeql_dir="",
        ql_base_name="",
        ql_file_path="",
        output_path="",
        run_juliet_path=run_juliet_path
    )[:500]  # Just check the beginning
    machine.context.action_type = get_action_type_from_prompt(formatted_prompt_preview)
    
    # Use agent action for agent mode with streaming JSON logging enabled
    action = create_agent_action(
        prompt_template=prompt_template,
        save_option='both',
        system_prompt="You are a CodeQL expert. Help modify CodeQL queries to capture more potential security vulnerabilities while maintaining accuracy. You have access to tools to write and test the queries. Use Write to save queries, Bash to test compilation and run queries, Read to examine files, and Grep to analyze CSV results. You must ensure both compilation success AND increased result count compared to origin.",
        allowed_tools=["Read", "Write", "Bash", "Edit", "Grep", "LS"],
        max_turns=20,  # Allow more turns for the mandatory verification loop
        enable_stream_logging=True
    )
    
    # Calculate paths for the current iteration
    iteration_dir = os.path.join(machine.context.output_dir, f"iteration_{machine.context.current_iteration}")
    query_results_dir = os.path.join(iteration_dir, "query_results")
    os.makedirs(query_results_dir, exist_ok=True)  # Ensure directory exists for agent
    
    ql_filename = os.path.basename(machine.context.ql_file_path)
    
    # Input: for iteration 1, from initial/query_results/; for others, from previous iteration/query_results/
    if machine.context.current_iteration == 1:
        input_origin_dir = os.path.join(machine.context.output_dir, "initial", "query_results")
    else:
        prev_iteration = machine.context.current_iteration - 1
        input_origin_dir = os.path.join(machine.context.output_dir, f"iteration_{prev_iteration}", "query_results")
    
    input_ql_path = os.path.join(input_origin_dir, ql_filename)
    # Output should be in current iteration's query_results directory
    output_path = os.path.join(query_results_dir, ql_filename)
    
    # Get the codeql directory path from original_ql_path
    # This path has already been converted to project codeql path in pipeline_config.py
    original_ql_path = machine.context.original_ql_path
    workspace_dir = machine.context.output_dir
    
    # Since original_ql_path is already pointing to the correct project codeql directory,
    # we just need to extract the directory path
    codeql_dir = os.path.dirname(original_ql_path)
    print(f"[QL Query Modification] Using codeql_dir: {codeql_dir}")
    

    # Copy the input query to codeql directory for modification
    import shutil
    ql_base_name = os.path.splitext(ql_filename)[0]  # Remove .ql extension
    modified_ql_path = os.path.join(codeql_dir, f'{ql_base_name}_modified.ql')
    shutil.copy2(input_ql_path, modified_ql_path)
    print(f"[QL Query Modification] Copied input query to: {modified_ql_path}")
    
    # Format the prompt for saving
    run_juliet_path = os.path.join(SCRIPT_DIR, 'run_juliet.py')
    # IMPORTANT: Do not pass actual Juliet test suite source code (C/C++ files) to Claude
    # to avoid overfitting. Only pass QL queries, query results, and metadata.
    formatted_prompt = prompt_template.format(
        cwe_number=machine.context.cwe_number,
        ql_file_path=input_ql_path,  # Use the input path (initial/ or previous iteration/)
        output_path=output_path,
        query_origin_dir=input_origin_dir,  # For checking origin result count
        codeql_dir=codeql_dir,  # For copying and testing
        ql_base_name=ql_base_name,  # For dynamic file naming
        extra_context=extra_context,
        library_paths_info=library_paths_info,
        broadening_strategies=broadening_strategies,
        recovery_strategies=recovery_strategies,
        run_juliet_path=run_juliet_path,
    )
    
    # Save the prompt to iteration/reports directory
    iteration_dir = os.path.join(machine.context.output_dir, f"iteration_{machine.context.current_iteration}")
    reports_dir = os.path.join(iteration_dir, "reports")
    os.makedirs(reports_dir, exist_ok=True)
    prompt_file = os.path.join(reports_dir, "01_modification_prompt.txt")
    with open(prompt_file, 'w') as f:
        f.write(formatted_prompt)
    
    # Call the action with the formatted parameters
    print(f"[QL Query Modification] Sending query to LLM for modification (type: {modification_type})...")
    result = action(machine, 
                  cwe_number=machine.context.cwe_number,
                  ql_file_path=input_ql_path,  # Use the input path (initial/ or previous iteration/)
                  output_path=output_path,
                  query_origin_dir=input_origin_dir,  # For checking origin result count
                  query_after_dir=query_results_dir,  # For library_paths.json location
                  codeql_dir=codeql_dir,  # For copying and testing
                  ql_base_name=ql_base_name,  # For dynamic file naming
                  extra_context=extra_context,
                  library_paths_info=library_paths_info,
                  broadening_strategies=broadening_strategies,
                  recovery_strategies=recovery_strategies,
                  run_juliet_path=run_juliet_path)
    print(f"[QL Query Modification] LLM response received")
    
    # Save the response too - agent mode returns a dict with 'response' key
    response_file = os.path.join(reports_dir, "01_modification_response.txt")
    if isinstance(result, dict) and 'response' in result:
        with open(response_file, 'w') as f:
            f.write(result['response'])
        # Store response for later use
        machine.context.modification_response = result['response']
    elif isinstance(result, str):
        with open(response_file, 'w') as f:
            f.write(result)
        machine.context.modification_response = result
    
    # Copy the modified query from codeql directory to output location
    if os.path.exists(modified_ql_path):
        try:
            shutil.copy2(modified_ql_path, output_path)
            print(f"[QL Query Modification] Copied modified query to: {output_path}")
            
            # Clean up the temporary modified file
            os.remove(modified_ql_path)
            print(f"[QL Query Modification] Cleaned up temporary file: {modified_ql_path}")
        except Exception as e:
            print(f"[QL Query Modification] Error handling modified file: {e}")
    else:
        print(f"[QL Query Modification] Warning: Modified file not found at {modified_ql_path}")
    
    # Copy .tmp/library_paths.json to reports directory if it exists
    tmp_library_paths = os.path.join(machine.context.output_dir, ".tmp", "library_paths.json")
    if os.path.exists(tmp_library_paths):
        try:
            reports_library_paths = os.path.join(reports_dir, "library_paths.json")
            shutil.copy2(tmp_library_paths, reports_library_paths)
            print(f"[QL Query Modification] Copied library paths to: {reports_library_paths}")
        except Exception as e:
            print(f"[QL Query Modification] Error copying library paths: {e}")
    
    return result


def exit_action(machine):
    """Exit action - returns the output path where agent saved the modified query."""
    import os
    
    # The agent should have saved the file to the output_path specified in the prompt
    iteration_dir = os.path.join(machine.context.output_dir, f"iteration_{machine.context.current_iteration}")
    query_results_dir = os.path.join(iteration_dir, "query_results")
    ql_filename = os.path.basename(machine.context.ql_file_path)
    output_path = os.path.join(query_results_dir, ql_filename)
    
    # Update context with the path where agent saved the file
    machine.context.modified_ql_path = output_path
    
    print(f"[QL Query Modification] Modified query saved by agent to: {output_path}")
    
    return output_path


# State machine configuration for query modification
state_definitions = {
    'ModifyQLQuery': {
        'action': modify_ql_query_action,
        'next_state_func': lambda result, machine: 'Exit',  # Go directly to Exit since agent saves the file
    },
    'Exit': {
        'action': exit_action,
        'next_state_func': None,
    },
}