import os
import json
import re
import sys
import subprocess
import argparse
import shutil
import time

log_enable = False

# Get the absolute path of the script directory
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# Docker configuration
# Use fixed container name instead of dynamic ID
DOCKER_CONTAINER_NAME = "ql-relax-container"

def ensure_container_running():
    """Ensure the QL-Relax container is running"""
    try:
        # Check if container exists and is running
        result = subprocess.run(
            ["docker", "ps", "--filter", f"name={DOCKER_CONTAINER_NAME}", "--format", "{{.Names}}"],
            capture_output=True, text=True, check=True
        )
        if DOCKER_CONTAINER_NAME in result.stdout:
            print(f"QL-Relax container '{DOCKER_CONTAINER_NAME}' is running")
            return DOCKER_CONTAINER_NAME
        
        # Check if container exists but is stopped
        result = subprocess.run(
            ["docker", "ps", "-a", "--filter", f"name={DOCKER_CONTAINER_NAME}", "--format", "{{.Names}}"],
            capture_output=True, text=True, check=True
        )
        if DOCKER_CONTAINER_NAME in result.stdout:
            print(f"Starting stopped container '{DOCKER_CONTAINER_NAME}'...")
            subprocess.run(["docker", "start", DOCKER_CONTAINER_NAME], check=True)
            return DOCKER_CONTAINER_NAME
            
    except subprocess.CalledProcessError:
        pass
    
    raise RuntimeError(
        f"Container '{DOCKER_CONTAINER_NAME}' not found. Please run:\n"
        f"1. Build the image: docker build -t ql-relax:latest .\n"
        f"2. Run the container: docker run -d --name {DOCKER_CONTAINER_NAME} -v $(pwd):/workspace ql-relax:latest\n"
        f"Or use docker-compose: docker-compose up -d --build"
    )

DOCKER_CONTAINER_ID = ensure_container_running()
DOCKER_CODEQL_PATH = "/opt/codeql/codeql"
HOST_WORKSPACE = SCRIPT_DIR  # Use relative path
DOCKER_WORKSPACE = "/workspace"

# Original path configuration (host paths)

cwe_dir = os.path.join(SCRIPT_DIR, "qlworkspace/origin/codeql/cpp/ql/src/")
codeql_path = DOCKER_CODEQL_PATH  # Use CodeQL in Docker
build_file = os.path.join(SCRIPT_DIR, "juliet-test-suite-c/build.sh")
juliet_source_root = os.path.join(SCRIPT_DIR, "juliet-test-suite-c/testcases")
julient_db_dir = os.path.join(SCRIPT_DIR, "juliet-test-suite-c/testcasesdb")
ql_workspace_dir = os.path.join(SCRIPT_DIR, "qlworkspace")
def host_to_docker_path(host_path):
    """Convert host path to Docker container path"""
    if host_path.startswith(HOST_WORKSPACE):
        return host_path.replace(HOST_WORKSPACE, DOCKER_WORKSPACE)
    return host_path

def run_in_docker(command):
    """Execute command in Docker container"""
    docker_cmd = ["docker", "exec", DOCKER_CONTAINER_ID] + command
    result = subprocess.run(docker_cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Error running command in Docker: {result.stderr}")
    return result

def run_in_docker_shell(command_str):
    """Execute shell command string in Docker container"""
    docker_cmd = f"docker exec {DOCKER_CONTAINER_ID} {command_str}"
    return os.system(docker_cmd)

def juliet_clean_all():
    subprocess.run(["python3", "juliet-test-suite-c/juliet.py", "-c", "--all"])

def juliet_clean_cwe(cwe_num):
    subprocess.run(["python3", "juliet-test-suite-c/juliet.py", "-c", str(cwe_num)])
def juliet_make_cwe(cwe_num):
    subprocess.run(["python3", "juliet-test-suite-c/juliet.py", "-g", "-m", str(cwe_num)])

def juliet_make_cwe_dump(cwe_num):
    # When executing in Docker container, need to use Docker path
    docker_juliet_py = host_to_docker_path(os.path.join(SCRIPT_DIR, "juliet-test-suite-c/juliet.py"))
    content = f"python3 {docker_juliet_py} -g -m {cwe_num}"
    with open(build_file, "w") as f:
        f.write(content)
def create_cwe_workspace(cwe_num):
    """Create separate workspace directories for each QL file of the specified CWE and clone codeql repository"""
    # Create main workspace directory
    os.makedirs(ql_workspace_dir, exist_ok=True)
    
    # Use optimized method to get all QL file information
    ql_info = get_all_ql_info_optimized(cwe_dir)
    cwe_to_files = ql_info['cwe_to_files']
    
    # Get all QL files corresponding to this CWE
    ql_files_for_cwe = cwe_to_files.get(cwe_num, [])
    
    if not ql_files_for_cwe:
        print(f"Warning: No QL files found for CWE-{cwe_num}")
        return []
    
    # First collect all workspace directories to be created
    workspace_to_create = []
    
    for ql_file_path in ql_files_for_cwe:
        # Extract directory name and file name from file path
        ql_dir = os.path.basename(os.path.dirname(ql_file_path))
        ql_name = os.path.splitext(os.path.basename(ql_file_path))[0]
        
        # Create workspace directory name: CWE number_QL file name
        cwe_dirname = f"CWE-{cwe_num:03d}_{ql_name}"
        cwe_workspace_path = os.path.join(ql_workspace_dir, cwe_dirname)
        
        workspace_to_create.append({
            'ql_file_path': ql_file_path,
            'ql_name': ql_name,
            'cwe_dirname': cwe_dirname,
            'cwe_workspace_path': cwe_workspace_path
        })
    
    # Display all workspace directories to be created
    print(f"\nThe following workspace directories will be created for CWE-{cwe_num}:")
    for i, workspace in enumerate(workspace_to_create, 1):
        print(f"  {i}. {workspace['cwe_workspace_path']}")
        print(f"     QL file: {workspace['ql_file_path']}")
    
    # Request user confirmation
    print(f"\nA total of {len(workspace_to_create)} workspace directories will be created.")
    
    print(f"\nStarting workspace creation...")
    created_workspaces = []
    
    for workspace in workspace_to_create:
        ql_file_path = workspace['ql_file_path']
        cwe_dirname = workspace['cwe_dirname']
        cwe_workspace_path = workspace['cwe_workspace_path']
        
        # If directory already exists, delete it first
        if os.path.exists(cwe_workspace_path):
            print(f"Directory {cwe_workspace_path} already exists, removing...")
            shutil.rmtree(cwe_workspace_path)
        
        # Create directory
        os.makedirs(cwe_workspace_path, exist_ok=True)
        
        # Use git clone to clone codeql repository
        target_codeql_path = os.path.join(cwe_workspace_path, "codeql")
        print(f"Cloning https://github.com/github/codeql.git to {target_codeql_path}...")
        clone_cmd = ["git", "clone", "https://github.com/github/codeql.git", target_codeql_path]
        result = subprocess.run(clone_cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            print(f"Error cloning repository: {result.stderr}")
            raise Exception(f"Failed to clone codeql repository: {result.stderr}")
        
        # Switch to specified commit
        print(f"Checking out commit 4ece8abc3032a266eb4b9839442d8be5084552ea...")
        checkout_cmd = ["git", "-C", target_codeql_path, "checkout", "4ece8abc3032a266eb4b9839442d8be5084552ea"]
        checkout_result = subprocess.run(checkout_cmd, capture_output=True, text=True)
        
        if checkout_result.returncode != 0:
            print(f"Error checking out commit: {checkout_result.stderr}")
            raise Exception(f"Failed to checkout commit: {checkout_result.stderr}")
        
        print(f"Successfully created workspace for {cwe_dirname} at {cwe_workspace_path}")
        created_workspaces.append(cwe_workspace_path)
    
    return created_workspaces

def parse_cwe_from_tags(content):
    """Parse CWE tags from QL file content"""
    cwe_numbers = set()
    # Use regular expressions to find all external/cwe/cwe-XXX format tags
    pattern = r'external/cwe/cwe-(\d+)'
    matches = re.findall(pattern, content, re.IGNORECASE)
    for match in matches:
        cwe_numbers.add(int(match))
    return cwe_numbers

def get_juliet_cwe_number():
    cwe_numbers = set()
    for root, dirs, files in os.walk(juliet_source_root):
        for dir_name in dirs:
            if dir_name.startswith(f"CWE"):
                cwe_number=dir_name.split("_")[0][3:]
                cwe_numbers.add(int(cwe_number))
    return sorted(list(cwe_numbers))
def create_juliet_database(cwe_num, overwrite=False):
    juliet_make_cwe_dump(cwe_num)
    # find sourceroot by cwe_num in juliet_source_root
    source_root = None
    for root, dirs, files in os.walk(juliet_source_root):
        for dir_name in dirs:
            if dir_name.startswith(f"CWE{cwe_num}_"):
                source_root = os.path.join(root, dir_name)
                break
        if source_root:
            break
    
    if not source_root:
        print(f"Unable to find source code directory corresponding to CWE{cwe_num}")
        sys.exit(1)

    # Ensure testcasesdb directory exists in Docker container
    docker_db_dir = host_to_docker_path(julient_db_dir)
    mkdir_cmd = ["mkdir", "-p", docker_db_dir]
    run_in_docker(mkdir_cmd)

    db_name = os.path.join(julient_db_dir, f"CWE{cwe_num}_cpp-db")

    if overwrite:
        juliet_clean_cwe(cwe_num)
        # Delete existing database directory in Docker container
        if os.path.exists(db_name):
            docker_db_name = host_to_docker_path(db_name)
            rm_command = ["rm", "-rf", docker_db_name]
            run_in_docker(rm_command)
            print(f"Removed existing database: {db_name}")
        
        # Convert paths to Docker paths
        docker_db_name = host_to_docker_path(db_name)
        docker_build_file = host_to_docker_path(build_file)
        docker_source_root = host_to_docker_path(source_root)
        
        command = [DOCKER_CODEQL_PATH, "database", "create", docker_db_name, "--language=cpp", 
                   "--command=" + docker_build_file, "--source-root", docker_source_root, "--overwrite"]
        result = run_in_docker(command)
        if result.returncode != 0:
            raise Exception(f"Failed to create database for CWE{cwe_num}: {result.stderr}")
        return db_name
    else:
        if os.path.exists(db_name):
            print(f"Database {db_name} already exists")
            return db_name
        # Convert paths to Docker paths
        docker_db_name = host_to_docker_path(db_name)
        docker_build_file = host_to_docker_path(build_file)
        docker_source_root = host_to_docker_path(source_root)
        
        command = [DOCKER_CODEQL_PATH, "database", "create", docker_db_name, "--language=cpp", 
                   "--command=" + docker_build_file, "--source-root", docker_source_root]
        result = run_in_docker(command)
        if result.returncode != 0:
            raise Exception(f"Failed to create database for CWE{cwe_num}: {result.stderr}")
        return db_name

def get_cwe_number(cwe_dir):
    cwe_numbers = set()
    for root, dirs, files in os.walk(cwe_dir):
        for file in files:
            if file.endswith(".ql"):
                # Get directory name
                with open(os.path.join(root, file), 'r') as f:
                    content = f.read()
                
                # Check if it's a valid query file (contains @kind tag)
                if "* @kind path-problem" not in content:
                    continue
                
                # Extract CWE number from directory name
                dir_name = os.path.basename(os.path.dirname(os.path.join(root, file)))
                if "CWE-" in dir_name:
                    try:
                        cwe_numbers.add(int(dir_name.split("-")[1]))
                    except:
                        pass
                
                # Extract CWE number from tags
                tag_cwes = parse_cwe_from_tags(content)
                cwe_numbers.update(tag_cwes)
                
    return sorted(list(cwe_numbers))  # Return sorted list of unique CWE numbers

def get_all_ql_info_optimized(cwe_dir):
    """
    Optimized version that collects all QL file information in a single pass.
    Returns a dictionary with:
    - 'cwe_numbers': set of all CWE numbers found
    - 'cwe_to_files': dict mapping CWE numbers to list of QL file paths
    - 'file_to_cwes': dict mapping QL file paths to set of CWE numbers
    """
    cwe_numbers = set()
    cwe_to_files = {}
    file_to_cwes = {}
    
    # Single pass through the directory tree
    for root, dirs, files in os.walk(cwe_dir):
        for file in files:
            if file.endswith(".ql"):
                file_path = os.path.join(root, file)
                abs_path = os.path.abspath(file_path)
                
                # Read file once
                try:
                    with open(file_path, 'r') as f:
                        content = f.read()
                except Exception as e:
                    print(f"Warning: Could not read {file_path}: {e}")
                    continue
                
                # Check if it's a valid query file
                if "* @kind path-problem" not in content:
                    continue
                
                file_cwes = set()
                
                # Extract CWE from directory name
                dir_name = os.path.basename(root)
                if "CWE-" in dir_name:
                    try:
                        cwe_num = int(dir_name.split("-")[1])
                        file_cwes.add(cwe_num)
                    except:
                        pass
                
                # Extract CWEs from tags
                tag_cwes = parse_cwe_from_tags(content)
                file_cwes.update(tag_cwes)
                
                # Update data structures
                if file_cwes:
                    cwe_numbers.update(file_cwes)
                    file_to_cwes[abs_path] = file_cwes
                    
                    for cwe_num in file_cwes:
                        if cwe_num not in cwe_to_files:
                            cwe_to_files[cwe_num] = []
                        cwe_to_files[cwe_num].append(abs_path)
    
    # Sort the file lists for consistent output
    for cwe_num in cwe_to_files:
        cwe_to_files[cwe_num].sort()
    
    return {
        'cwe_numbers': cwe_numbers,
        'cwe_to_files': cwe_to_files,
        'file_to_cwes': file_to_cwes
    }

def get_ql_list(cwe_dir):
    """Get list of all QL files and their associated CWE numbers"""
    ql_list = []
    # Use os.walk to recursively traverse directories
    for root, dirs, files in os.walk(cwe_dir):
        for file in files:
            if file.endswith(".ql"):
                file_path = os.path.join(root, file)
                with open(file_path, 'r') as f:
                    content = f.read()
                # Check if it's a valid query file (contains @kind tag)
                if "* @kind path-problem" not in content:
                    continue
                
                # Get all CWE numbers associated with this query
                cwe_numbers = set()
                
                # Extract CWE number from directory name
                dir_name = os.path.basename(root)
                if "CWE-" in dir_name:
                    try:
                        cwe_numbers.add(int(dir_name.split("-")[1]))
                    except:
                        pass
                
                # Extract CWE number from tags
                tag_cwes = parse_cwe_from_tags(content)
                cwe_numbers.update(tag_cwes)
                
                # Add an entry for each CWE number
                abs_path = os.path.abspath(file_path)
                for cwe_num in cwe_numbers:
                    ql_list.append((abs_path, cwe_num))
    
    return ql_list

def get_ql_files_by_cwe(cwe_dir, cwe_num):
    """Get all QL file paths for specified CWE number (including matches by directory name and tags)"""
    ql_files = []
    # Match both formats with and without leading zeros
    target_patterns = [f"CWE-{cwe_num}", f"CWE-{cwe_num:03d}"]
    
    for root, dirs, files in os.walk(cwe_dir):
        for file in files:
            if file.endswith(".ql"):
                file_path = os.path.join(root, file)
                with open(file_path, 'r') as f:
                    content = f.read()
                
                # Check if it's a valid query file (contains @kind tag)
                if "* @kind path-problem" not in content:
                    continue
                
                # Method 1: Check if directory name matches CWE number
                dir_matches = os.path.basename(root) in target_patterns
                
                # Method 2: Check if file content tags contain this CWE
                tag_cwes = parse_cwe_from_tags(content)
                tag_matches = cwe_num in tag_cwes
                
                # If either method matches, add this file
                if dir_matches or tag_matches:
                    ql_files.append(os.path.abspath(file_path))
                    
    # Remove duplicates (as a file may match through multiple methods)
    return sorted(list(set(ql_files)))

def run_codeql_query(ql_path, cwe_num, output_dir="qlresult"):
    # Create output directory
    os.makedirs(output_dir, exist_ok=True)
    db_path = os.path.join(julient_db_dir, f"CWE{cwe_num}_cpp-db")
    
    try:
        # Get query name as output file name
        ql_name = os.path.splitext(os.path.basename(ql_path))[0]
        cwe_name = os.path.basename(os.path.dirname(ql_path))
        query_name = f"{cwe_name}_{ql_name}"
        bqrs_file = os.path.join(output_dir, f"{query_name}.bqrs")
        csv_file = os.path.join(output_dir, f"{query_name}.csv")
        sarif_file = os.path.join(output_dir, f"{query_name}.sarif")
        
        # Step 1: Run query, output BQRS format
        # Convert paths to Docker paths
        docker_db_path = host_to_docker_path(db_path)
        docker_bqrs_file = host_to_docker_path(bqrs_file)
        docker_ql_path = host_to_docker_path(ql_path)
        
        # Check if we need to generate CSV for function dump
        generate_csv = ql_name == "function_dump"
        
        if generate_csv:
            # For function_dump, we need to run query and generate CSV
            cmd_run = f'{DOCKER_CODEQL_PATH} query run --database="{docker_db_path}" --output="{docker_bqrs_file}" "{docker_ql_path}"'
            print(f"Running query: {query_name}")
            print(f"Docker command: docker exec {DOCKER_CONTAINER_ID} {cmd_run}")
            exit_code = run_in_docker_shell(cmd_run)
            
            if exit_code == 0:
                # Step 2: Convert BQRS to CSV
                docker_csv_file = host_to_docker_path(csv_file)
                cmd_decode = f'{DOCKER_CODEQL_PATH} bqrs decode --format=csv --output="{docker_csv_file}" "{docker_bqrs_file}"'
                decode_exit_code = run_in_docker_shell(cmd_decode)
                
                if decode_exit_code == 0:
                    print(f"Successfully executed query: {query_name}")
                    print(f"CSV output: {csv_file}")
                    results.append({"query": query_name, "status": "success", "csv_file": csv_file})
                else:
                    print(f"Failed to decode query results: {query_name}")
                    results.append({"query": query_name, "status": "failed"})
            else:
                print(f"Failed to execute query: {query_name}")
                results.append({"query": query_name, "status": "failed"})
        else:
            # Step 3: Use database analyze to generate complete SARIF format
            docker_sarif_file = host_to_docker_path(sarif_file)
            cmd_analyze = f'{DOCKER_CODEQL_PATH} database analyze --format=sarifv2.1.0 --output="{docker_sarif_file}" "{docker_db_path}" "{docker_ql_path}"'
            print(f"Generating SARIF with full data flow information...")
            sarif_exit_code = run_in_docker_shell(cmd_analyze)
                
            if sarif_exit_code == 0:
                print(f"Successfully executed query: {query_name}")
                print(f"SARIF output: {sarif_file}")
                results.append({"query": query_name, "status": "success", "sarif_file": sarif_file})
            else:
                print(f"Failed to execute query: {query_name}")
                results.append({"query": query_name, "status": "failed"})
            
    except Exception as e:
        print(f"Error executing query {ql_path}: {str(e)}")
        results.append({"query": query_name, "status": "error", "error": str(e)})
            


if __name__ == "__main__":
    # Add command line argument parsing
    parser = argparse.ArgumentParser(description='Run Juliet test suite with CodeQL')
    parser.add_argument('--create-db', action='store_true', help='Create CodeQL database')
    parser.add_argument('--cwe', type=int, help='CWE number to process')
    parser.add_argument('--all', action='store_true', help='Process all CWEs')
    parser.add_argument('--overwrite', action='store_true', help='Overwrite existing database')
    parser.add_argument('--run-queries', action='store_true', help='Run CodeQL queries')
    parser.add_argument('--ql', type=str, help='Specify QL script to run (absolute path)')
    parser.add_argument('--output', type=str, default='qlresult', help='Output directory for query results (default: qlresult)')
    parser.add_argument('--list-common-cwes', action='store_true', help='List all CWE numbers that have both Juliet database and queries')
    parser.add_argument('--create-workspace', action='store_true', help='Create workspace directory structure for CWEs')
    parser.add_argument('--use-old-method', action='store_true', help='Use the old (slow) method for listing common CWEs (for comparison)')
    args = parser.parse_args()
    
    if args.create_db:
        if args.all:
            # Create databases for all CWEs
            juliet_cwe_numbers = get_juliet_cwe_number()
            print(f"Found {len(juliet_cwe_numbers)} CWEs to process: {juliet_cwe_numbers}")
            for cwe_num in juliet_cwe_numbers:
                print(f"\n{'='*60}")
                print(f"Creating database for CWE {cwe_num}...")
                try:
                    db_path = create_juliet_database(cwe_num, overwrite=args.overwrite)
                    print(f"Database created: {db_path}")
                except Exception as e:
                    print(f"Error creating database for CWE {cwe_num}: {e}")
                    continue
        elif args.cwe:
            # Create database for single CWE
            print(f"Creating database for CWE {args.cwe}...")
            db_path = create_juliet_database(args.cwe, overwrite=args.overwrite)
            print(f"Database created: {db_path}")
        else:
            print("Error: --create-db requires either --cwe <number> or --all")
            parser.print_help()
    elif args.run_queries:
        # Run query mode
        results = []
        
        if args.ql:
            # If specific QL script is specified
            if not os.path.exists(args.ql):
                print(f"Error: QL file not found: {args.ql}")
                sys.exit(1)
            
            if not args.cwe:
                print("Error: --ql requires --cwe <number> to specify which database to use")
                parser.print_help()
                sys.exit(1)
            
            # Check if database exists
            db_path = os.path.join(julient_db_dir, f"CWE{args.cwe}_cpp-db")
            if not os.path.exists(db_path):
                print(f"Error: Database for CWE{args.cwe} not found. Please create it first with --create-db --cwe {args.cwe}")
                sys.exit(1)
            
            print(f"Running specified QL script: {args.ql}")
            run_codeql_query(args.ql, args.cwe, args.output)
        else:
            # Original logic: run all matching queries
            ql_list = get_ql_list(cwe_dir)
            print("Found {} query-CWE pairs".format(len(ql_list)))
            
            # Count unique query files
            unique_queries = len(set([ql[0] for ql in ql_list]))
            print("Found {} unique queries".format(unique_queries))
            print(ql_list)
            
            cwe_number = get_cwe_number(cwe_dir)
            print("Found {} cwe in ql".format(len(cwe_number)))
            
            juliet_cwe_number = get_juliet_cwe_number()
            print("Found {} juliet cwe".format(len(juliet_cwe_number)))
            
            if args.all:
                # Run all matching CWEs
                cwe_number_to_run = []
                for cwe_num in cwe_number:
                    if cwe_num in juliet_cwe_number:
                        cwe_number_to_run.append(cwe_num)
            elif args.cwe:
                # If CWE is specified, only run that CWE
                cwe_number_to_run = [args.cwe] if args.cwe in juliet_cwe_number else []
            else:
                print("Error: --run-queries requires either --cwe <number> or --all")
                parser.print_help()
                sys.exit(1)
            
            print("Found {} cwe to run".format(len(cwe_number_to_run)))
            print(cwe_number_to_run)
            
            # Track executed queries to avoid duplicates
            executed_queries = set()
            
            for ql_path, cwe_num in ql_list:
                if cwe_num in cwe_number_to_run:
                    # Create unique identifier to avoid duplicate execution of same query for same CWE
                    query_id = f"{ql_path}_{cwe_num}"
                    if query_id not in executed_queries:
                        executed_queries.add(query_id)
                        results.append(run_codeql_query(ql_path, cwe_num, args.output))
        
        # Save execution results to log file:
        if log_enable == True:
            with open(os.path.join(args.output, "execution_log.json"), "w") as f:
                json.dump(results, f, indent=2)
        
            print(f"Execution completed. Check {args.output} directory for results.")

    elif args.list_common_cwes:
        start_time = time.time()
        
        # Get CWE numbers from Juliet
        juliet_start = time.time()
        juliet_cwe_numbers = get_juliet_cwe_number()
        juliet_time = time.time() - juliet_start
        print(f"Found {len(juliet_cwe_numbers)} CWEs in Juliet test suite (took {juliet_time:.2f}s)")
        print(juliet_cwe_numbers)
        
        if args.use_old_method:
            # Use old method (for performance comparison)
            print("Using OLD method for scanning QL files...")
            ql_start = time.time()
            query_cwe_numbers = get_cwe_number(cwe_dir)
            ql_time = time.time() - ql_start
            print(f"Found {len(query_cwe_numbers)} CWEs in queries (took {ql_time:.2f}s)")
            print(query_cwe_numbers)
            
            # Find CWE numbers that exist in both
            common_cwes = sorted([cwe for cwe in query_cwe_numbers if cwe in juliet_cwe_numbers])
            
            print(f"\nFound {len(common_cwes)} CWEs that have both Juliet database and queries:")
            print(f"Common CWEs: {common_cwes}")
            
            # Detailed output of each CWE and its corresponding QL files
            print("\nDetailed list with QL files:")
            detail_start = time.time()
            for cwe in common_cwes:
                print(f"\nCWE-{cwe}:")
                ql_files = get_ql_files_by_cwe(cwe_dir, cwe)
                if ql_files:
                    for ql_file in ql_files:
                        print(f"  - {ql_file}")
                else:
                    print(f"  No QL files found (this shouldn't happen)")
            detail_time = time.time() - detail_start
            print(f"\nDetail scanning took: {detail_time:.2f}s")
        else:
            # Use optimized version to get all QL information (single traversal)
            print("Using OPTIMIZED method for scanning QL files...")
            ql_start = time.time()
            ql_info = get_all_ql_info_optimized(cwe_dir)
            query_cwe_numbers = sorted(list(ql_info['cwe_numbers']))
            cwe_to_files = ql_info['cwe_to_files']
            ql_time = time.time() - ql_start
            
            print(f"Found {len(query_cwe_numbers)} CWEs in queries (took {ql_time:.2f}s)")
            print(query_cwe_numbers)
            
            # Find CWE numbers that exist in both
            common_cwes = sorted([cwe for cwe in query_cwe_numbers if cwe in juliet_cwe_numbers])
            
            print(f"\nFound {len(common_cwes)} CWEs that have both Juliet database and queries:")
            print(f"Common CWEs: {common_cwes}")
            
            # Detailed output of each CWE and its corresponding QL files (using cached data, no need to scan again)
            print("\nDetailed list with QL files:")
            detail_start = time.time()
            for cwe in common_cwes:
                print(f"\nCWE-{cwe}:")
                ql_files = cwe_to_files.get(cwe, [])
                if ql_files:
                    for ql_file in ql_files:
                        print(f"  - {ql_file}")
                else:
                    print(f"  No QL files found (this shouldn't happen)")
            detail_time = time.time() - detail_start
            print(f"\nDetail output took: {detail_time:.2f}s (using cached data)")
        
        total_time = time.time() - start_time
        print(f"\nTotal execution time: {total_time:.2f}s")
    elif args.create_workspace:
        # Create workspace directory structure
        if args.all:
            # Get all common CWEs (using optimized method)
            juliet_cwe_numbers = get_juliet_cwe_number()
            ql_info = get_all_ql_info_optimized(cwe_dir)
            query_cwe_numbers = sorted(list(ql_info['cwe_numbers']))
            common_cwes = sorted([cwe for cwe in query_cwe_numbers if cwe in juliet_cwe_numbers])
            
            print(f"Creating workspace for {len(common_cwes)} CWEs...")
            for cwe_num in common_cwes:
                try:
                    create_cwe_workspace(cwe_num)
                except Exception as e:
                    print(f"Error creating workspace for CWE {cwe_num}: {e}")
                    continue
        elif args.cwe:
            # Create workspace for single CWE
            print(f"Creating workspace for CWE {args.cwe}...")
            try:
                create_cwe_workspace(args.cwe)
            except Exception as e:
                print(f"Error creating workspace for CWE {args.cwe}: {e}")
        else:
            print("Error: --create-workspace requires either --cwe <number> or --all")
            parser.print_help()
    else:
        parser.print_help()


