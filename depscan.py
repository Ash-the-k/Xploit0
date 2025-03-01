import requests
import os
import time
from packaging import requirements
from rich.console import Console
from rich.table import Table
import json

# OSV API URL
OSV_API_URL = "https://api.osv.dev/v1/query"

def fetch_vulnerabilities_osv(package_name, version):
    """
    Fetch vulnerabilities for a given package and version using the OSV API.
    """
    # Clean version string to remove comparison operators
    clean_version = version.replace('==', '').replace('>=', '').replace('<=', '').strip()
    
    query = {
        "package": {"name": package_name, "ecosystem": "PyPI"},
        "version": clean_version
    }
    
    try:
        response = requests.post(OSV_API_URL, json=query)
        if response.status_code != 200:
            print(f"Error fetching vulnerabilities for {package_name}: {response.status_code}")
            return []

        data = response.json()
        vulnerabilities = []
        for vuln in data.get("vulns", []):
            vuln_id = vuln.get("id")
            description = vuln.get("details")
            
            # Extract and convert severity to float if possible
            try:
                severity_score = float(vuln.get("severity", [{}])[0].get("score", 0))
                severity = "High" if severity_score >= 7.0 else ("Medium" if severity_score >= 4.0 else "Low")
            except (ValueError, TypeError, IndexError):
                severity = "Unknown"
            
            vulnerabilities.append({
                "id": vuln_id,
                "description": description,
                "severity": severity
            })

        return vulnerabilities
    except Exception as e:
        print(f"Error checking {package_name}: {str(e)}")
        return []

def parse_requirements_txt(file_path):
    """
    Parse requirements.txt to extract dependencies.
    """
    if not os.path.exists(file_path):
        print(f"[!] {file_path} not found in current directory")
        return {}
    with open(file_path, "r") as f:
        lines = f.readlines()

    deps = {}
    for line in lines:
        line = line.strip()
        if line and not line.startswith("#"):
            req = requirements.Requirement(line)
            deps[req.name] = str(req.specifier)
    return deps

def parse_package_json(file_path):
    """
    Parse package.json to extract dependencies.
    """
    if not os.path.exists(file_path):
        print(f"[!] {file_path} not found in current directory")
        return {}
    with open(file_path, "r") as f:
        data = json.load(f)
        deps = {}
        for pkg in data.get("packages", []):
            if isinstance(pkg, list) and len(pkg) == 2:
                deps[pkg[0]] = pkg[1]
        return deps

def print_vulnerabilities(package, vulnerabilities):
    """
    Print vulnerabilities in a table format.
    """
    console = Console()
    if vulnerabilities:
        table = Table(title=f"Vulnerabilities for {package}")
        table.add_column("ID", style="cyan")
        table.add_column("Severity", style="red")
        table.add_column("Description", style="green")

        for vuln in vulnerabilities:
            severity_style = {
                "High": "bold red",
                "Medium": "yellow",
                "Low": "green",
                "Unknown": "blue"
            }.get(vuln["severity"], "blue")
            
            # Truncate description if too long
            description = vuln["description"]
            if description and len(description) > 80:
                description = description[:77] + "..."
            
            table.add_row(
                vuln["id"],
                f"[{severity_style}]{vuln['severity']}[/{severity_style}]",
                description
            )

        console.print(table)
    else:
        console.print(f"[green]No vulnerabilities found for {package}.[/green]")

def check_vulnerabilities(dependencies):
    """
    Check vulnerabilities for a list of dependencies using OSV API.
    """
    vulnerabilities_found = []
    console = Console()
    
    if not dependencies:
        console.print("[yellow]No dependencies found to check[/yellow]")
        return vulnerabilities_found

    for package, version in dependencies.items():
        console.print(f"\n[bold blue]Checking {package}@{version}...[/bold blue]")
        vulnerabilities = fetch_vulnerabilities_osv(package, version)
        
        if vulnerabilities:
            vulnerabilities_found.extend(vulnerabilities)
            print_vulnerabilities(package, vulnerabilities)
        else:
            console.print(f"[green]✓ No vulnerabilities found for {package}@{version}[/green]")
        
        time.sleep(1)  # Add a delay to avoid rate limiting
    
    return vulnerabilities_found

def get_dependencies():
    """
    Get all dependencies from both requirements.txt and packages.json
    """
    dependencies = []
    
    # Check requirements.txt
    if os.path.exists("requirements.txt"):
        req_deps = parse_requirements_txt("requirements.txt")
        for name, version in req_deps.items():
            # Clean version string
            clean_version = version.replace('==', '').replace('>=', '').replace('<=', '').strip()
            dependencies.append({
                "name": name,
                "version": clean_version,
                "source": "requirements.txt"
            })

    # Check packages.json
    if os.path.exists("packages.json"):
        pkg_deps = parse_package_json("packages.json")
        for name, version in pkg_deps.items():
            dependencies.append({
                "name": name,
                "version": version,
                "source": "packages.json"
            })

    return dependencies

def main():
    console = Console()
    total_vulnerabilities = []

    # Check requirements.txt
    console.print("\n[bold]Scanning requirements.txt...[/bold]")
    if os.path.exists("requirements.txt"):
        requirements_txt_deps = parse_requirements_txt("requirements.txt")
        if requirements_txt_deps:
            vulns = check_vulnerabilities(requirements_txt_deps)
            total_vulnerabilities.extend(vulns)
        else:
            console.print("[yellow]No dependencies found in requirements.txt[/yellow]")
    else:
        console.print("[yellow]requirements.txt not found[/yellow]")

    # Check packages.json
    console.print("\n[bold]Scanning packages.json...[/bold]")
    if os.path.exists("packages.json"):
        package_json_deps = parse_package_json("packages.json")
        if package_json_deps:
            vulns = check_vulnerabilities(package_json_deps)
            total_vulnerabilities.extend(vulns)
        else:
            console.print("[yellow]No dependencies found in packages.json[/yellow]")
    else:
        console.print("[yellow]packages.json not found[/yellow]")

    # Print final summary
    console.print("\n[bold]Scan Summary:[/bold]")
    if total_vulnerabilities:
        console.print(f"[red]Found {len(total_vulnerabilities)} total vulnerabilities![/red]")
    else:
        console.print("[green]✓ No vulnerabilities found in any dependencies![/green]")

if __name__ == "__main__":
    main()