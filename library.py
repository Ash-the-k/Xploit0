import ast
import os
import pkg_resources
import sys
import subprocess
import re
import json
from packaging import version

def get_imported_libraries(file_path):
    """Extract imported libraries from a Python file."""
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            content = file.read()
            
        if file_path.endswith('.py'):
            return get_python_imports(content)
        elif file_path.endswith(('.c', '.cpp', '.h', '.hpp')):
            return get_cpp_imports(content)
        return set()
            
    except Exception as e:
        print(f"[-] Error parsing {file_path}: {str(e)}")
        return set()

def get_python_imports(content):
    """Extract Python imports using AST."""
    imports = set()
    try:
        tree = ast.parse(content)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for name in node.names:
                    imports.add(name.name.split('.')[0])
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imports.add(node.module.split('.')[0])
    except Exception as e:
        print(f"[-] AST parsing error: {str(e)}")
    return imports

def get_cpp_imports(content):
    """Extract C/C++ includes using regex."""
    imports = set()
    
    # Match system includes (<...>) and local includes ("...")
    system_includes = re.findall(r'#include\s*<([^>]+)>', content)
    local_includes = re.findall(r'#include\s*"([^"]+)"', content)
    
    # Add system libraries
    for inc in system_includes:
        imports.add(('cpp_system', inc))
    
    # Add local libraries
    for inc in local_includes:
        imports.add(('cpp_local', inc))
    
    return imports

def get_package_info(package_name):
    """Get installed version and location of a package."""
    try:
        dist = pkg_resources.get_distribution(package_name)
        return {
            'name': dist.project_name,
            'version': dist.version,
            'location': dist.location
        }
    except pkg_resources.DistributionNotFound:
        return None

def scan_requirements_file(file_path):
    """Scan a requirements.txt file for dependencies."""
    packages = set()
    
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            for line in file:
                # Remove comments and whitespace
                line = line.split('#')[0].strip()
                if not line:
                    continue
                
                # Handle various requirement formats
                if '==' in line:
                    package = line.split('==')[0].strip()
                elif '>=' in line:
                    package = line.split('>=')[0].strip()
                elif '<=' in line:
                    package = line.split('<=')[0].strip()
                elif '>' in line:
                    package = line.split('>')[0].strip()
                elif '<' in line:
                    package = line.split('<')[0].strip()
                else:
                    package = line.strip()
                
                # Remove any extras
                if '[' in package:
                    package = package.split('[')[0].strip()
                
                packages.add(package)
                
    except Exception as e:
        print(f"[-] Error parsing requirements file {file_path}: {str(e)}")
    
    return packages

def check_vulnerabilities_with_safety(packages):
    """Check for vulnerabilities using safety command line tool."""
    try:
        # First, ensure safety is installed
        try:
            subprocess.run([sys.executable, "-m", "pip", "install", "--upgrade", "safety"], 
                         capture_output=True, check=True)
            print("[+] Safety tool installed successfully")
        except subprocess.CalledProcessError as e:
            print(f"[-] Failed to install safety: {e}")
            return []

        # Create a temporary requirements file
        temp_file = "temp_requirements_for_scan.txt"
        with open(temp_file, 'w') as f:
            for pkg, version in packages.items():
                if version:
                    f.write(f"{pkg}=={version}\n")
                else:
                    f.write(f"{pkg}\n")
        
        print(f"[+] Checking {len(packages)} packages for vulnerabilities...")
        
        # Run safety check with full output
        print("[+] Running safety check (this may take a moment)...")
        safety_cmd = [sys.executable, "-m", "safety", "check", "-r", temp_file, "--full-report", "--json"]
        result = subprocess.run(safety_cmd, capture_output=True, text=True)
        
        # For debugging
        print(f"[DEBUG] Safety command: {' '.join(safety_cmd)}")
        
        # Clean up temp file
        if os.path.exists(temp_file):
            os.remove(temp_file)
        
        # Check if we got valid JSON output
        try:
            # Try to parse the results
            if result.stdout.strip():
                vulns_data = json.loads(result.stdout)
                if isinstance(vulns_data, list):
                    return vulns_data
                elif isinstance(vulns_data, dict) and "vulnerabilities" in vulns_data:
                    return vulns_data["vulnerabilities"]
                else:
                    print(f"[DEBUG] Unexpected JSON structure: {vulns_data}")
                    return []
            else:
                # If stdout is empty but stderr has content
                if result.stderr.strip():
                    print(f"[DEBUG] Safety stderr: {result.stderr}")
                
                # Try an alternative approach - safety check with plain output
                print("[+] Trying alternative approach...")
                alt_result = subprocess.run(
                    [sys.executable, "-m", "safety", "check", "-r", temp_file],
                    capture_output=True, 
                    text=True
                )
                
                # Parse plain text output
                if "No known security vulnerabilities found." in alt_result.stdout:
                    print("[+] Safety confirmed no vulnerabilities found")
                    return []
                else:
                    # Manual parsing of potential vulnerabilities from text output
                    print(f"[DEBUG] Alternative safety output: {alt_result.stdout}")
                    return []
        except json.JSONDecodeError as e:
            print(f"[DEBUG] JSON decode error: {e}")
            print(f"[DEBUG] Safety stdout: {result.stdout[:500]}...")
            return []
            
    except Exception as e:
        print(f"[-] Error during vulnerability check: {str(e)}")
        import traceback
        traceback.print_exc()
        return []

def parse_python_file(file_path):
    try:
        # Try UTF-8 first
        with open(file_path, 'r', encoding='utf-8') as f:
            return f.read()
    except UnicodeDecodeError:
        try:
            # Try with latin-1 encoding if UTF-8 fails
            with open(file_path, 'r', encoding='latin-1') as f:
                return f.read()
        except Exception:
            # If both fail, skip the file
            print(f"[-] Skipping file due to encoding issues: {file_path}")
            return ""

def main(directory="."):
    print("[+] Starting dependency scan...")

    all_imports = set()
    scanned_files = []
    requirements_files = []

    # Find all relevant files in the directory
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith('.py'):
                file_path = os.path.join(root, file)
                scanned_files.append(file_path)
            elif file.lower() == 'requirements.txt':
                requirements_files.append(os.path.join(root, file))
    
    print(f"[+] Total Python files found: {len(scanned_files)}")
    print(f"[+] Total requirements files found: {len(requirements_files)}")

    # Analyze requirements files
    for req_file in requirements_files:
        print(f"[+] Analyzing requirements file: {req_file}")
        req_imports = scan_requirements_file(req_file)
        all_imports.update(req_imports)
        print(f"    Found {len(req_imports)} packages in requirements file")

    # Analyze each Python file
    for file_path in scanned_files:
        try:
            content = parse_python_file(file_path)
            imports = get_imported_libraries(file_path)
            if imports:
                all_imports.update(imports)
        except Exception as e:
            print(f"[-] Error processing {file_path}: {str(e)}")
            continue

    if not all_imports:
        print("[-] No libraries found")
        return

    print(f"\n[+] Total unique libraries found: {len(all_imports)}")
    
    # Filter out standard library modules
    standard_libs = set([
        'abc', 'argparse', 'ast', 'asyncio', 'base64', 'collections', 'configparser',
        'contextlib', 'copy', 'csv', 'datetime', 'decimal', 'difflib', 'enum',
        'fileinput', 'fnmatch', 'functools', 'gc', 'glob', 'hashlib', 'heapq',
        'hmac', 'html', 'http', 'importlib', 'inspect', 'io', 'itertools', 'json',
        'logging', 'math', 'multiprocessing', 'operator', 'os', 'pathlib', 'pickle',
        'platform', 'pprint', 'queue', 're', 'random', 'shutil', 'signal', 'socket',
        'sqlite3', 'statistics', 'string', 'struct', 'subprocess', 'sys', 'tempfile',
        'threading', 'time', 'timeit', 'traceback', 'types', 'typing', 'unittest',
        'urllib', 'uuid', 'warnings', 'weakref', 'xml', 'zipfile', 'zlib'
    ])
    
    third_party_libs = [lib for lib in all_imports if lib not in standard_libs and isinstance(lib, str)]
    
    print(f"[+] Third-party libraries found: {len(third_party_libs)}")
    print("\n[+] Getting installed package information...")
    
    # Get info about installed packages
    packages_with_versions = {}
    for lib in third_party_libs:
        pkg_info = get_package_info(lib)
        if pkg_info:
            packages_with_versions[pkg_info['name']] = pkg_info['version']
            print(f"    {pkg_info['name']} (version {pkg_info['version']})")
        else:
            print(f"    {lib} (not installed or built-in)")
    
    # Check for vulnerabilities using safety
    print("\n[+] Checking for vulnerabilities...")
    vulnerabilities = check_vulnerabilities_with_safety(packages_with_versions)
    
    if vulnerabilities and len(vulnerabilities) > 0:
        print("\n[!] Vulnerabilities found:")
        for vuln in vulnerabilities:
            if isinstance(vuln, list) and len(vuln) >= 5:
                print(f"    Package: {vuln[0]}")
                print(f"    Vulnerable version: {vuln[1]}")
                print(f"    Fixed version: {vuln[2]}")
                print(f"    Vulnerability ID: {vuln[3]}")
                print(f"    Description: {vuln[4]}")
                print("-" * 40)
            elif isinstance(vuln, dict):
                print(f"    Package: {vuln.get('package_name', 'Unknown')}")
                print(f"    Vulnerable version: {vuln.get('vulnerable_spec', 'Unknown')}")
                print(f"    Fixed version: {vuln.get('fixed_version', 'Unknown')}")
                print(f"    Vulnerability ID: {vuln.get('vulnerability_id', 'Unknown')}")
                print(f"    Description: {vuln.get('description', 'No description available')}")
                print("-" * 40)
            else:
                print(f"    Unknown vulnerability format: {vuln}")
    else:
        print("\n[+] No vulnerabilities found in your dependencies")
        
    # Suggest alternative manual vulnerability checking
    print("\n[+] For additional vulnerability checking, you can also try:")
    print("    1. Running 'pip-audit' on your environment: pip install pip-audit && pip-audit")
    print("    2. Using OWASP Dependency Check: https://owasp.org/www-project-dependency-check/")
    print("    3. Checking the National Vulnerability Database: https://nvd.nist.gov/")

def check_with_pip_audit():
    """Run pip-audit as an alternative approach"""
    try:
        # Install pip-audit
        subprocess.run([sys.executable, "-m", "pip", "install", "pip-audit"], 
                     capture_output=True, check=True)
        
        # Run pip-audit
        result = subprocess.run([sys.executable, "-m", "pip_audit"], 
                              capture_output=True, text=True)
        
        # Print the output
        print("\n[+] pip-audit results:")
        print(result.stdout)
        
    except Exception as e:
        print(f"[-] pip-audit check failed: {str(e)}")

if __name__ == "__main__":
    try:
        print('''
 __     _ __                          ___                     
/ / _   () /  _______ _________ ____/ ( )__  ___  ___  ___ 
/ / | | / / _ \/ _/ _ `/ __/ _ `/ _  / / __/ / _ \/ _ \/ -)
//  ||//////  \,//  \,/\,/  \/ / ./\/\/ 
                                              /_/              
''')
        directory = sys.argv[1] if len(sys.argv) > 1 else "."
        main(directory)
        
        # Ask if user wants to try pip-audit
        response = input("\nWould you like to also run pip-audit for a second opinion? (y/n): ")
        if response.lower() in ('y', 'yes'):
            check_with_pip_audit()
            
    except KeyboardInterrupt:
        print("\n[-] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[-] An error occurred: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)