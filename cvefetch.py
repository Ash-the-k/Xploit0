import requests
import json
import pandas as pd
from rich.console import Console
from rich.table import Table
import depscan
import os
import time
from datetime import datetime
from colorama import init, Fore, Style
import pkg_resources

# Initialize colorama for Windows support
init()

# NVD API Endpoint
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
console = Console()

# Add your NVD API key here
API_KEY = '02586fa2-ed24-4dbb-bdb8-782288531511'  # Your API key

def check_package(package_name, version):
    """Check a single package for vulnerabilities"""
    print(f"\nChecking {Fore.CYAN}{package_name} {version}{Style.RESET_ALL} from requirements.txt...")
    
    try:
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        headers = {
            'apiKey': API_KEY,
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json'
        }
        params = {
            "keywordSearch": f"{package_name}",
            "resultsPerPage": 50
        }
        
        print(f"Sending request to NVD API for {package_name} {version} (page 1)...")
        response = requests.get(url, headers=headers, params=params)
        
        if response.status_code == 200:
            data = response.json()
            total_results = data.get('totalResults', 0)
            print(f"Total results available: {total_results}")
            
            vulnerabilities = []
            if total_results > 0:
                for vuln in data.get('vulnerabilities', []):
                    cve_data = {
                        'Package': package_name,
                        'Version': version,
                        'CVE_ID': vuln.get('cve', {}).get('id', ''),
                        'Description': vuln.get('cve', {}).get('descriptions', [{}])[0].get('value', ''),
                        'CVSS': vuln.get('cve', {}).get('metrics', {}).get('cvssMetricV31', [{}])[0].get('cvssData', {}).get('baseScore', 'N/A'),
                        'Severity': vuln.get('cve', {}).get('metrics', {}).get('cvssMetricV31', [{}])[0].get('cvssData', {}).get('baseSeverity', 'N/A')
                    }
                    vulnerabilities.append(cve_data)
            
            if vulnerabilities:
                print(f"{Fore.YELLOW}! Found {len(vulnerabilities)} CVEs for {package_name} {version}{Style.RESET_ALL}")
                return vulnerabilities
            else:
                print(f"{Fore.GREEN}✓ No CVEs found for {package_name} {version}{Style.RESET_ALL}")
                return []
                
        else:
            print(f"{Fore.RED}Error: Status code {response.status_code} - {response.text}{Style.RESET_ALL}")
            return []
            
    except Exception as e:
        print(f"{Fore.RED}Error checking {package_name}: {str(e)}{Style.RESET_ALL}")
        return []
    
    finally:
        time.sleep(2)  # Increased delay between requests

def parse_cve_data(cve_list):
    """Extracts relevant details from CVE data."""
    records = []
    for item in cve_list:
        cve = item["cve"]
        cve_id = cve.get("id", "N/A")
        description = cve.get("descriptions", [{}])[0].get("value", "N/A")
        cvss_v3 = cve.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {})
        cvss_score = cvss_v3.get("baseScore", "N/A")
        severity = cvss_v3.get("baseSeverity", "N/A")
        references = [ref["url"] for ref in cve.get("references", [])]
        
        records.append({
            "cve_id": cve_id,
            "description": description,
            "cvss_score": cvss_score,
            "severity": severity,
            "references": references
        })
    
    return records

def print_cve_results(package, version, cve_records):
    """Print CVE results in a nice table format."""
    if not cve_records:
        console.print(f"[green]✓ No CVEs found for {package} {version}[/green]")
        return

    table = Table(title=f"CVEs for {package} {version}")
    table.add_column("CVE ID", style="cyan")
    table.add_column("Severity", style="red")
    table.add_column("CVSS", style="yellow")
    table.add_column("Description", style="white")

    for record in cve_records:
        severity_style = {
            "CRITICAL": "bold red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "green"
        }.get(record["severity"], "white")

        description = record["description"]
        if len(description) > 100:
            description = description[:97] + "..."

        table.add_row(
            record["cve_id"],
            f"[{severity_style}]{record['severity']}[/{severity_style}]",
            str(record["cvss_score"]),
            description
        )

    console.print(table)

def get_installed_packages():
    """Get list of installed packages from requirements.txt"""
    try:
        with open('requirements.txt', 'r') as f:
            requirements = f.readlines()
        
        packages = []
        for req in requirements:
            req = req.strip()
            if req and not req.startswith('#'):
                try:
                    name, version = req.split('==')
                    packages.append({'name': name, 'version': version})
                except ValueError:
                    print(f"{Fore.YELLOW}! Warning: Skipping invalid requirement: {req}{Style.RESET_ALL}")
        return packages
    except Exception as e:
        print(f"{Fore.RED}✗ Error reading requirements.txt: {str(e)}{Style.RESET_ALL}")
        return []

def main():
    print(f"\n{Fore.CYAN}Fetching CVEs for all dependencies...{Style.RESET_ALL}\n")
    
    all_vulnerabilities = []
    
    try:
        # Read requirements.txt
        with open('requirements.txt', 'r') as f:
            requirements = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        
        # Process each package
        for req in requirements:
            try:
                package_name, version = req.split('==')
                vulnerabilities = check_package(package_name, version)
                all_vulnerabilities.extend(vulnerabilities)
            except ValueError:
                print(f"{Fore.YELLOW}! Skipping invalid requirement: {req}{Style.RESET_ALL}")
        
        # Save results if any found
        if all_vulnerabilities:
            df = pd.DataFrame(all_vulnerabilities)
            df.to_csv('cve_data.csv', index=False)
            print(f"\n{Fore.GREEN}✓ Saved {len(all_vulnerabilities)} vulnerabilities to cve_data.csv{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.GREEN}✓ No vulnerabilities found for any package{Style.RESET_ALL}")
            
    except FileNotFoundError:
        print(f"{Fore.RED}Error: requirements.txt not found{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}Error: {str(e)}{Style.RESET_ALL}")

if __name__ == "__main__":
    if not API_KEY:
        console.print("""
[yellow]Note: For better results, set your NVD API key:[/yellow]
[dim]On Windows:[/dim]
    set NVD_API_KEY=your-api-key-here
[dim]On Linux/Mac:[/dim]
    export NVD_API_KEY=your-api-key-here

[blue]You can get an API key from: https://nvd.nist.gov/developers/request-an-api-key[/blue]
""")
    
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}! Scan interrupted by user{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}✗ Error: {str(e)}{Style.RESET_ALL}")
