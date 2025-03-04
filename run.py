import subprocess
import time
import os
from datetime import datetime
from colorama import init, Fore, Style
import pandas as pd
import json

# Initialize colorama
init()

class SecurityAnalysis:
    def __init__(self):
        self.timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.results_dir = 'analysis_results'
        self.ensure_directories()

    def ensure_directories(self):
        """Create necessary directories"""
        directories = [
            self.results_dir,
            'vulnerability_reports',
            'models',
            'data',
            'logs'
        ]
        for directory in directories:
            os.makedirs(directory, exist_ok=True)

    def run_script(self, script_name, description):
        """Run a Python script and capture its output exactly as shown in terminal"""
        log_file = os.path.join('logs', f'{script_name}_{self.timestamp}.log')
        print(f"\n{Fore.CYAN}Running {description} ({script_name})...{Style.RESET_ALL}")
        
        try:
            with open(log_file, 'w', encoding='utf-8') as f:
                # Write header with timestamp
                header = f"""
==========================================
Running {description} ({script_name})
Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
==========================================

"""
                f.write(header)
                print(header)

                # Run the script and capture output in real-time
                process = subprocess.Popen(
                    ['python', script_name],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    bufsize=1,
                    universal_newlines=True
                )

                # Real-time output capture
                while True:
                    # Read stdout
                    output = process.stdout.readline()
                    if output:
                        # Write to log and print to terminal exactly as is
                        f.write(output)
                        print(output, end='')
                        f.flush()

                    # Read stderr
                    error = process.stderr.readline()
                    if error:
                        # Write to log and print to terminal in red
                        f.write(error)
                        print(f"{Fore.RED}{error}{Style.RESET_ALL}", end='')
                        f.flush()

                    # Check if process has finished
                    if process.poll() is not None:
                        break

                # Capture any remaining output
                remaining_output, remaining_error = process.communicate()
                if remaining_output:
                    f.write(remaining_output)
                    print(remaining_output, end='')
                if remaining_error:
                    f.write(remaining_error)
                    print(f"{Fore.RED}{remaining_error}{Style.RESET_ALL}", end='')

                # Write footer
                footer = f"""
==========================================
Completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Return code: {process.returncode}
Status: {'Success' if process.returncode == 0 else 'Failed'}
==========================================
"""
                f.write(footer)
                print(footer)

                return process.returncode == 0, log_file

        except Exception as e:
            error_msg = f"""
==========================================
ERROR: {str(e)}
Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
==========================================
"""
            print(f"{Fore.RED}{error_msg}{Style.RESET_ALL}")
            with open(log_file, 'a', encoding='utf-8') as f:
                f.write(error_msg)
            return False, log_file

    def run_analysis(self):
        """Run all analysis scripts in sequence and capture ALL terminal output"""
        print(f"\n{Fore.GREEN}Starting Security Analysis at {self.timestamp}{Style.RESET_ALL}\n")
        
        # Create master log file for all output
        master_log = os.path.join('logs', f'complete_analysis_{self.timestamp}.log')
        
        scripts = [
            ('depscan.py', 'Dependency Scanning'),
            ('cvefetch.py', 'CVE Data Fetching'),
            ('cvedata.py', 'CVE Data Processing'),
            ('preproscsv.py', 'Data Preprocessing'),
            ('modeltrain.py', 'Model Training'),
            ('predict.py', 'Vulnerability Prediction')
        ]

        with open(master_log, 'w', encoding='utf-8') as log:
            # Write analysis start header
            header = f"""
==============================================
COMPLETE SECURITY ANALYSIS OUTPUT
Started at: {self.timestamp}
==============================================

"""
            log.write(header)
            print(header)

            results = []
            for script_name, description in scripts:
                script_header = f"""
----------------------------------------------
Running: {description} ({script_name})
Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
----------------------------------------------
"""
                log.write(script_header)
                print(script_header)

                try:
                    # Run script and capture ALL output in real-time
                    process = subprocess.Popen(
                        ['python', script_name],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        bufsize=1,
                        universal_newlines=True
                    )

                    # Real-time output capture
                    while True:
                        output = process.stdout.readline()
                        if output:
                            log.write(output)
                            print(output, end='')
                            log.flush()

                        error = process.stderr.readline()
                        if error:
                            log.write(error)
                            print(f"{Fore.RED}{error}{Style.RESET_ALL}", end='')
                            log.flush()

                        if process.poll() is not None:
                            break

                    # Get remaining output
                    remaining_out, remaining_err = process.communicate()
                    if remaining_out:
                        log.write(remaining_out)
                        print(remaining_out, end='')
                    if remaining_err:
                        log.write(remaining_err)
                        print(f"{Fore.RED}{remaining_err}{Style.RESET_ALL}", end='')

                    script_footer = f"""
Script completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Return code: {process.returncode}
Status: {'Success' if process.returncode == 0 else 'Failed'}
----------------------------------------------
"""
                    log.write(script_footer)
                    print(script_footer)

                    results.append({
                        'script': script_name,
                        'description': description,
                        'success': process.returncode == 0,
                        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    })

                except Exception as e:
                    error_msg = f"""
ERROR running {script_name}: {str(e)}
----------------------------------------------
"""
                    log.write(error_msg)
                    print(f"{Fore.RED}{error_msg}{Style.RESET_ALL}")
                    results.append({
                        'script': script_name,
                        'description': description,
                        'success': False,
                        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    })

            # Write final summary
            summary = f"""
==============================================
ANALYSIS SUMMARY
Completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Total scripts run: {len(scripts)}
Successful: {sum(1 for r in results if r['success'])}
Failed: {sum(1 for r in results if not r['success'])}
==============================================
"""
            log.write(summary)
            print(summary)

            # Start Streamlit dashboard
            print(f"{Fore.GREEN}Starting Streamlit Dashboard...{Style.RESET_ALL}")
            subprocess.Popen(['streamlit', 'run', 'dashboard.py'])

            return master_log, results

    def generate_report(self, results):
        """Generate a comprehensive report"""
        report_path = os.path.join(self.results_dir, f'analysis_report_{self.timestamp}.txt')
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write("Security Analysis Report\n")
            f.write("=" * 50 + "\n\n")
            
            # Write results for each script
            for script, result in results.items():
                f.write(f"\n{script} Results\n")
                f.write("-" * 20 + "\n")
                f.write(f"Status: {'Success' if result['success'] else 'Failed'}\n")
                f.write(f"Timestamp: {result['timestamp']}\n")
                f.write(f"Log File: {result['log_file']}\n")
                
                # Include snippet of log file
                if os.path.exists(result['log_file']):
                    with open(result['log_file'], 'r', encoding='utf-8') as log:
                        f.write("\nLog Excerpt:\n")
                        f.write("-" * 10 + "\n")
                        f.write(log.read()[-500:] + "\n")  # Last 500 characters
                f.write("\n")

            # Add vulnerability summary if available
            if os.path.exists('cve_data.csv'):
                df = pd.read_csv('cve_data.csv')
                f.write("\nVulnerability Summary\n")
                f.write("-" * 20 + "\n")
                f.write(f"Total Vulnerabilities: {len(df)}\n")
                severity_counts = df['Severity'].value_counts()
                for severity, count in severity_counts.items():
                    f.write(f"{severity}: {count}\n")

        print(f"\n{Fore.GREEN}✓ Report generated: {report_path}{Style.RESET_ALL}")

def main():
    print(f"\n{Fore.CYAN}Starting Security Analysis Suite{Style.RESET_ALL}")
    
    # Run the analysis
    analyzer = SecurityAnalysis()
    analyzer.run_analysis()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Analysis interrupted by user{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}Error: {str(e)}{Style.RESET_ALL}")
