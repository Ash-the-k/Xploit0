import subprocess
import os
from colorama import Fore, Style

def run_analysis():
    # Get absolute paths to all scripts
    scripts = [
        (os.path.abspath('depscan.py'), 'Dependency Scanning'),
        (os.path.abspath('cvefetch.py'), 'CVE Data Fetching'),
        (os.path.abspath('cvedata.py'), 'CVE Data Processing'),
        (os.path.abspath('preproscsv.py'), 'Data Preprocessing'),
        (os.path.abspath('modeltrain.py'), 'Model Training'),
        (os.path.abspath('predict.py'), 'Vulnerability Prediction')
        (os.path.abspath('dashboard.py'), 'Dashboard')

    ]

    print(f"Current working directory: {os.getcwd()}")

    for script_path, description in scripts:
        print(f"\n{Fore.YELLOW}Starting {description}...{Style.RESET_ALL}")

        if not os.path.exists(script_path):
            print(f"{Fore.RED}Script not found: {script_path}{Style.RESET_ALL}")
            continue

        print(f"Executing script at: {script_path}")
        
        try:
            subprocess.run(['python3', script_path], check=True)
            print(f"{Fore.GREEN}{description} completed successfully.{Style.RESET_ALL}")
        except subprocess.CalledProcessError as e:
            print(f"{Fore.RED}Error during {description}: {e}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}Unexpected error during {description}: {e}{Style.RESET_ALL}")

if _name_ == "_main_":
    run_analysis()