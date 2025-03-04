import os
import sys
import github
from github import Github
import library
import tempfile
import shutil
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import print as rprint
from rich.table import Table
from rich.live import Live
from detect_secrets.core.secrets_collection import SecretsCollection
from detect_secrets.core import baseline
import json
import requests
from packaging import version
import subprocess
from typing import Tuple, List, Dict, Optional
import toml
import yaml
from pathlib import Path

console = Console()

def clone_pr(repo_url, pr_number, access_token):
    """Clone the PR branch and return the path to the cloned repository."""
    try:
        g = Github(access_token)
        with console.status("[bold blue]Accessing repository...") as status:
            console.print(f"[bold cyan]➜[/] Attempting to access repository: [green]{repo_url}[/]")
            repo = g.get_repo(repo_url)
            console.print(f"[bold cyan]➜[/] Attempting to access PR [green]#{pr_number}[/]")
            pr = repo.get_pull(pr_number)
            
            # Create a temporary directory
            temp_dir = tempfile.mkdtemp()
            
            # Clone the PR branch
            console.print("[bold cyan]➜[/] Cloning repository...")
            os.system(f"git clone {pr.head.repo.clone_url} {temp_dir}")
            os.system(f"cd {temp_dir} && git checkout {pr.head.ref}")
            
            return temp_dir
    except github.GithubException as e:
        console.print(f"[bold red]✗ GitHub API Error:[/] {e.status} - {e.data.get('message', '')}")
        if e.status == 404:
            console.print(Panel.fit(
                "\n".join([
                    "[yellow]Please verify:[/]",
                    f"• Repository '{repo_url}' exists",
                    f"• PR #{pr_number} exists",
                    "• Your token has correct permissions"
                ]),
                title="[red]Verification Required",
                border_style="red"
            ))
        return None
    except Exception as e:
        console.print(f"[bold red]✗ Error cloning PR:[/] {str(e)}")
        return None

def get_modified_dependency_files(repo_url, pr_number, access_token):
    """Get list of modified requirements files and Python files in the PR."""
    try:
        g = Github(access_token)
        repo = g.get_repo(repo_url)
        pr = repo.get_pull(pr_number)
        
        modified_files = []
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Scanning modified files...", total=None)
            for file in pr.get_files():
                if file.filename.endswith(('.py', 'requirements.txt')):
                    modified_files.append(file.filename)
            progress.update(task, completed=True)
        
        return modified_files
    except Exception as e:
        console.print(f"[bold red]✗ Error getting modified files:[/] {str(e)}")
        return []

def scan_for_basic_issues(directory) -> Tuple[bool, List[Dict]]:
    """Basic security scan without semgrep"""
    try:
        with console.status("[bold blue]Running security analysis...") as status:
            issues = []
            
            # Basic pattern checks
            patterns = {
                'password': ('Password in code', 'HIGH'),
                'secret': ('Secret in code', 'HIGH'),
                'api_key': ('API Key in code', 'HIGH'),
                'token': ('Token in code', 'HIGH'),
                'TODO': ('TODO found', 'LOW'),
                'FIXME': ('FIXME found', 'LOW'),
            }
            
            # Scan all Python files
            for root, _, files in os.walk(directory):
                for file in files:
                    if file.endswith('.py'):
                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, 'r', encoding='utf-8') as f:
                                for i, line in enumerate(f, 1):
                                    for pattern, (message, severity) in patterns.items():
                                        if pattern.lower() in line.lower():
                                            issues.append({
                                                'path': file_path,
                                                'line': i,
                                                'message': message,
                                                'severity': severity
                                            })
                        except Exception as e:
                            console.print(f"[yellow]Warning: Could not read {file_path}: {str(e)}")
            
            if not issues:
                console.print("[bold green]✓[/] No basic security issues found")
                return True, []
            
            # Create results table
            issues_table = Table(title="Security Scan Results", show_header=True, header_style="bold magenta")
            issues_table.add_column("Severity", style="red")
            issues_table.add_column("File", style="cyan")
            issues_table.add_column("Issue", style="yellow")
            issues_table.add_column("Line", justify="right")
            
            for issue in issues:
                issues_table.add_row(
                    issue['severity'],
                    os.path.basename(issue['path']),
                    issue['message'],
                    str(issue['line'])
                )
            
            console.print(issues_table)
            
            # Return False if any HIGH severity issues found
            has_high_severity = any(i['severity'] == 'HIGH' for i in issues)
            return (not has_high_severity), issues
            
    except Exception as e:
        console.print(f"[bold red]✗ Error in security scanning:[/] {str(e)}")
        return False, []

def check_nvd_vulnerabilities(package_name: str, version_str: str) -> List[Dict]:
    """Check National Vulnerability Database (NVD) for known vulnerabilities."""
    try:
        # Using NVD API v2.0
        base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {
            'keywordSearch': f"{package_name}@{version_str}",
            'keywordExactMatch': True
        }
        
        response = requests.get(base_url, params=params)
        response.raise_for_status()
        
        data = response.json()
        vulnerabilities = []
        
        for vuln in data.get('vulnerabilities', []):
            cve = vuln.get('cve', {})
            metrics = cve.get('metrics', {}).get('cvssMetricV31', [{}])[0]
            
            if metrics:
                vulnerabilities.append({
                    'id': cve.get('id', ''),
                    'description': cve.get('descriptions', [{}])[0].get('value', ''),
                    'severity': metrics.get('cvssData', {}).get('baseSeverity', 'UNKNOWN'),
                    'score': metrics.get('cvssData', {}).get('baseScore', 0.0)
                })
        
        return vulnerabilities
    except Exception as e:
        console.print(f"[bold yellow]⚠ Warning: Could not check NVD for {package_name}:[/] {str(e)}")
        return []

def calculate_risk_score(sast_findings: List[Dict], secrets_count: int, vulnerabilities: List[Dict]) -> Tuple[int, Dict]:
    """Calculate overall risk score based on all findings."""
    try:
        # Base score weights
        weights = {
            'sast': {
                'ERROR': 10,    # Critical SAST issues
                'WARNING': 5,   # High SAST issues
                'INFO': 2       # Medium SAST issues
            },
            'secrets': 15,      # Each secret found
            'vulnerabilities': {
                'CRITICAL': 10,
                'HIGH': 7,
                'MEDIUM': 4,
                'LOW': 1
            }
        }
        
        score_breakdown = {
            'sast_score': 0,
            'secrets_score': 0,
            'vulnerability_score': 0
        }
        
        # Calculate SAST score
        for finding in sast_findings:
            severity = finding.get('extra', {}).get('severity', 'INFO')
            score_breakdown['sast_score'] += weights['sast'].get(severity, 0)
        
        # Calculate secrets score
        score_breakdown['secrets_score'] = secrets_count * weights['secrets']
        
        # Calculate vulnerability score
        for vuln in vulnerabilities:
            severity = vuln['severity']
            score_breakdown['vulnerability_score'] += weights['vulnerabilities'].get(severity, 0)
        
        total_score = sum(score_breakdown.values())
        
        # Risk levels
        risk_level = "LOW"
        if total_score > 100:
            risk_level = "CRITICAL"
        elif total_score > 50:
            risk_level = "HIGH"
        elif total_score > 25:
            risk_level = "MEDIUM"
        
        return total_score, {
            'risk_level': risk_level,
            'breakdown': score_breakdown
        }
    except Exception as e:
        console.print(f"[bold yellow]⚠ Warning: Error calculating risk score:[/] {str(e)}")
        return 0, {'risk_level': 'UNKNOWN', 'breakdown': {}}

def parse_dependencies(file_path: Path) -> List[Tuple[str, str]]:
    """Parse dependencies from various package manager files."""
    try:
        file_name = file_path.name
        deps = []
        
        if file_name == 'requirements.txt':
            # Python requirements.txt
            with open(file_path) as f:
                for line in f:
                    line = line.strip()
                    if '==' in line:
                        pkg, ver = line.split('==')
                        deps.append((pkg.strip(), ver.strip()))
        
        elif file_name == 'package.json':
            # Node.js dependencies
            with open(file_path) as f:
                data = json.load(f)
                for dep_type in ['dependencies', 'devDependencies']:
                    if dep_type in data:
                        for pkg, ver in data[dep_type].items():
                            # Remove version prefix characters
                            ver = ver.lstrip('^~')
                            deps.append((pkg, ver))
        
        elif file_name == 'Cargo.toml':
            # Rust dependencies
            with open(file_path) as f:
                data = toml.load(f)
                if 'dependencies' in data:
                    for pkg, info in data['dependencies'].items():
                        if isinstance(info, str):
                            deps.append((pkg, info))
                        elif isinstance(info, dict) and 'version' in info:
                            deps.append((pkg, info['version']))
        
        elif file_name == 'go.mod':
            # Go dependencies
            with open(file_path) as f:
                for line in f:
                    if 'require' in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            deps.append((parts[1], parts[2]))
        
        elif file_name == 'Gemfile.lock':
            # Ruby dependencies
            with open(file_path) as f:
                current_pkg = None
                for line in f:
                    if line.startswith('    '):
                        if current_pkg and '(' in line and ')' in line:
                            ver = line.split('(')[1].split(')')[0]
                            deps.append((current_pkg, ver))
                    else:
                        current_pkg = line.strip()
        
        return deps
    except Exception as e:
        console.print(f"[bold yellow]⚠ Warning: Error parsing dependencies from {file_path}:[/] {str(e)}")
        return []

def save_scan_results(risk_score: int, risk_details: Dict, vulnerabilities: List[Dict]):
    """Save scan results to a JSON file for GitHub Actions."""
    results = {
        "risk_score": risk_score,
        "risk_level": risk_details["risk_level"],
        "breakdown": risk_details["breakdown"],
        "vulnerabilities": [
            {
                "package": vuln["package"],
                "version": vuln["version"],
                "cve": vuln["id"],
                "severity": vuln["severity"],
                "score": vuln["score"]
            }
            for vuln in vulnerabilities
        ]
    }
    
    with open('scan-results.json', 'w') as f:
        json.dump(results, f, indent=2)

def analyze_pr_dependencies(repo_url, pr_number, access_token, strict_mode=False):
    """Analyze dependencies in a pull request for vulnerabilities."""
    console.print(Panel.fit(
        f"Analyzing PR #{pr_number} for {repo_url}",
        title="[bold blue]PR Analysis",
        border_style="blue"
    ))
    
    # Clone the PR
    temp_dir = clone_pr(repo_url, pr_number, access_token)
    if not temp_dir:
        return False
    
    try:
        # Get modified files
        modified_files = get_modified_dependency_files(repo_url, pr_number, access_token)
        console.print(f"[bold green]✓[/] Found [cyan]{len(modified_files)}[/] modified dependency-related files")
        
        # Run security scan (using basic scan instead of semgrep)
        scan_passed, scan_findings = scan_for_basic_issues(temp_dir)
        
        # Check dependencies against NVD
        vuln_table = Table(title="Vulnerability Scan Results", show_header=True, header_style="bold magenta")
        vuln_table.add_column("Package", style="cyan")
        vuln_table.add_column("Version", style="yellow")
        vuln_table.add_column("CVE", style="red")
        vuln_table.add_column("Severity", style="red")
        vuln_table.add_column("Score", justify="right")
        
        all_vulnerabilities = []
        
        # Check requirements.txt
        req_file = Path(temp_dir) / 'requirements.txt'
        if req_file.exists():
            deps = parse_dependencies(req_file)
            for pkg, ver in deps:
                vulns = check_nvd_vulnerabilities(pkg, ver)
                for vuln in vulns:
                    vuln_table.add_row(
                        pkg,
                        ver,
                        vuln['id'],
                        vuln['severity'],
                        str(vuln['score'])
                    )
                all_vulnerabilities.extend(vulns)
        
        if all_vulnerabilities:
            console.print(vuln_table)
        
        # Calculate risk score
        risk_score = len(scan_findings) * 10 + len(all_vulnerabilities) * 5
        risk_level = "LOW"
        if risk_score > 100:
            risk_level = "CRITICAL"
        elif risk_score > 50:
            risk_level = "HIGH"
        elif risk_score > 25:
            risk_level = "MEDIUM"
        
        # Create Risk Score Panel
        console.print(Panel.fit(
            f"Risk Score: {risk_score}\nRisk Level: {risk_level}",
            title="[bold blue]Risk Assessment",
            border_style="blue"
        ))
        
        return risk_score <= 50
        
    except Exception as e:
        console.print(f"[bold red]✗ Error analyzing PR:[/] {str(e)}")
        return False
    finally:
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)

def scan_for_secrets(directory) -> Tuple[bool, int]:
    """Scan for hardcoded secrets in the codebase."""
    try:
        with console.status("[bold blue]Scanning for secrets...") as status:
            secrets = baseline.create(
                path=directory,
                exclude_files_regex='',
                exclude_lines_regex=''
            )
            
            secrets_count = 0
            secrets_table = Table(title="Secrets Scan Results", show_header=True, header_style="bold magenta")
            secrets_table.add_column("File", style="cyan")
            secrets_table.add_column("Type", style="yellow")
            secrets_table.add_column("Line", justify="right")
            
            if secrets and secrets.json():
                for filename, file_results in secrets.json().items():
                    for secret in file_results:
                        secrets_count += 1
                        secrets_table.add_row(
                            filename,
                            secret['type'],
                            str(secret['line_number'])
                        )
            
            if secrets_count > 0:
                console.print(secrets_table)
            else:
                console.print("[bold green]✓[/] No hardcoded secrets found")
            
            return secrets_count == 0, secrets_count
    except Exception as e:
        console.print(f"[bold red]✗ Error in secrets scanning:[/] {str(e)}")
        return False, 0

def main():
    """Main function to run the PR vulnerability scanner."""
    # Support both manual and GitHub Actions usage
    if os.getenv('GITHUB_ACTIONS'):
        repo_url = os.getenv('GITHUB_REPOSITORY')
        pr_number = int(os.getenv('PR_NUMBER'))
        github_token = os.getenv('GITHUB_TOKEN')
        strict_mode = True
    elif len(sys.argv) < 4:
        console.print(Panel.fit(
            "\n".join([
                "[white]Usage: python gitpr.py <repo_url> <pr_number> <github_token> [--strict]",
                "Example: python gitpr.py owner/repo 123 ghp_yourtoken --strict"
            ]),
            title="[yellow]Usage Instructions",
            border_style="yellow"
        ))
        sys.exit(1)
    else:
        repo_url = sys.argv[1]
        pr_number = int(sys.argv[2])
        github_token = sys.argv[3]
        strict_mode = "--strict" in sys.argv
    
    console.print(Panel.fit(
        '''[cyan]
  ____  ____    ____                                 
 |  _ \|  _ \  / ___|  ___ __ _ _ __  _ __   ___ _ __ 
 | |) | |) | \___ \ / _/ _` | ' \| '_ \ / _ \ '|
 |  _/|  _ <   ___) | (| (_| | | | | | | |  __/ |   
 ||   || \\ |/ \\,|| ||| ||\|_|   
        [/]''',
        title="[bold blue]PR Security Scanner",
        border_style="blue"
    ))
    
    try:
        success = analyze_pr_dependencies(repo_url, pr_number, github_token, strict_mode)
        if not success and strict_mode:
            console.print("[bold red]✗ Security checks failed in strict mode[/]")
            sys.exit(1)
    except KeyboardInterrupt:
        console.print("\n[bold red]✗ Scan interrupted by user[/]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[bold red]✗ An error occurred:[/] {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()