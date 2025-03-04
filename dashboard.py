import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import os
from datetime import datetime
import glob
import json
import subprocess
import logging
import requests
import time

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def syft_scan_repository(local_path, image_tag):
    """
    Build a Docker image from the local repository and scan it with Syft.
    Returns the SBOM as a parsed JSON object.
    """
    dockerfile_path = os.path.join(local_path, "Dockerfile")
    if not os.path.exists(dockerfile_path):
        logger.info("No Dockerfile found, generating a default Dockerfile...")
        default_dockerfile = """FROM python:3.9-slim
WORKDIR /app
COPY . /app
RUN if [ -f requirements.txt ]; then pip install --no-cache-dir -r requirements.txt; fi
CMD ["python", "app.py"]
"""
        with open(dockerfile_path, "w") as f:
            f.write(default_dockerfile)
    
    # Build the Docker image
    logger.info(f"Building Docker image with tag: {image_tag}")
    build_cmd = ["docker", "build", "-t", image_tag, local_path]
    process = subprocess.run(build_cmd, capture_output=True, text=True)
    if process.returncode != 0:
        logger.error("Docker build failed: " + process.stderr)
        raise Exception("Docker build failed")
    
    # Run syft scan on the built image and capture JSON output
    logger.info(f"Running Syft scan on image: {image_tag}")
    syft_cmd = ["syft", image_tag, "-o", "json"]
    syft_process = subprocess.run(syft_cmd, capture_output=True, text=True)
    if syft_process.returncode != 0:
        logger.error("Syft scan failed: " + syft_process.stderr)
        raise Exception("Syft scan failed")
    
    try:
        sbom = json.loads(syft_process.stdout)
    except Exception as e:
        logger.error("Failed to parse Syft output: " + str(e))
        sbom = {"raw": syft_process.stdout}
    
    return sbom

def load_latest_predictions():
    """Load the most recent predictions file"""
    prediction_files = glob.glob('vulnerability_reports/predictions_*.csv')
    if not prediction_files:
        return None
    latest_file = max(prediction_files, key=os.path.getctime)
    return pd.read_csv(latest_file), latest_file

def load_logs():
    """Load logs from all script outputs"""
    logs = {}
    
    # Define scripts to check
    scripts = [
        'scanner.py',
        'library.py',
        'depscan.py',
        'gitpr.py',
        'cvefetch.py',
        'cvedata.py',
        'preproscsv.py',
        'depriskai.py',
        'modeltrain.py',
        'predict.py'
    ]
    
    # Load logs from analysis_results directory
    log_files = glob.glob('analysis_results/*.txt')
    if log_files:
        latest_log = max(log_files, key=os.path.getctime)
        with open(latest_log, 'r') as f:
            logs['analysis_report'] = f.read()
    
    return logs

def create_severity_chart(df):
    """Create severity distribution chart"""
    severity_counts = df['Predicted_Severity'].value_counts()
    fig = px.pie(
        values=severity_counts.values,
        names=severity_counts.index,
        title='Vulnerability Severity Distribution',
        color=severity_counts.index,
        color_discrete_map={
            'CRITICAL': 'red',
            'HIGH': 'orange',
            'MEDIUM': 'yellow',
            'LOW': 'green'
        }
    )
    return fig

def create_package_severity_chart(df):
    """Create package-wise severity distribution"""
    package_severity = pd.crosstab(df['Package'], df['Predicted_Severity'])
    fig = px.bar(
        package_severity,
        title='Package-wise Vulnerability Distribution',
        barmode='stack',
        color_discrete_map={
            'CRITICAL': 'red',
            'HIGH': 'orange',
            'MEDIUM': 'yellow',
            'LOW': 'green'
        }
    )
    fig.update_layout(xaxis_title='Package', yaxis_title='Number of Vulnerabilities')
    return fig

def create_cvss_severity_scatter(df):
    """Create CVSS vs Predicted Severity scatter plot"""
    fig = px.scatter(
        df,
        x='CVSS',
        y='Predicted_Severity',
        color='Predicted_Severity',
        hover_data=['CVE_ID', 'Package'],
        title='CVSS Score vs Predicted Severity',
        color_discrete_map={
            'CRITICAL': 'red',
            'HIGH': 'orange',
            'MEDIUM': 'yellow',
            'LOW': 'green'
        }
    )
    return fig

def main():
    st.set_page_config(page_title="Vulnerability Analysis Dashboard", layout="wide")
    
    # Sidebar
    st.sidebar.title("Navigation")
    page = st.sidebar.radio("Go to", ["Dashboard", "Logs", "Analysis Report"])
    
    if page == "Dashboard":
        st.title("Vulnerability Analysis Dashboard")
        
        # Load data
        data_load = load_latest_predictions()
        if data_load is None:
            st.error("No prediction files found. Please run predictions first.")
            return
            
        df, latest_file = data_load
        
        # Display last update time
        st.sidebar.write(f"Last Updated: {datetime.fromtimestamp(os.path.getctime(latest_file)).strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Filters
        st.sidebar.title("Filters")
        selected_packages = st.sidebar.multiselect(
            "Select Packages",
            options=sorted(df['Package'].unique()),
            default=sorted(df['Package'].unique())
        )
        
        selected_severities = st.sidebar.multiselect(
            "Select Severities",
            options=sorted(df['Predicted_Severity'].unique()),
            default=sorted(df['Predicted_Severity'].unique())
        )
        
        # Filter data
        filtered_df = df[
            (df['Package'].isin(selected_packages)) &
            (df['Predicted_Severity'].isin(selected_severities))
        ]
        
        # Summary metrics
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Vulnerabilities", len(filtered_df))
        with col2:
            st.metric("Critical Vulnerabilities", len(filtered_df[filtered_df['Predicted_Severity'] == 'CRITICAL']))
        with col3:
            st.metric("Affected Packages", filtered_df['Package'].nunique())
        with col4:
            st.metric("Average CVSS", f"{filtered_df['CVSS'].mean():.2f}")
        
        # Charts
        col1, col2 = st.columns(2)
        with col1:
            st.plotly_chart(create_severity_chart(filtered_df), use_container_width=True)
        with col2:
            st.plotly_chart(create_package_severity_chart(filtered_df), use_container_width=True)
        
        st.plotly_chart(create_cvss_severity_scatter(filtered_df), use_container_width=True)
        
        # Detailed vulnerability table
        st.subheader("Vulnerability Details")
        st.dataframe(
            filtered_df[['CVE_ID', 'Package', 'CVSS', 'Predicted_Severity', 'Description']],
            use_container_width=True
        )
        
    elif page == "Logs":
        st.title("Script Execution Logs")
        
        logs = load_logs()
        
        if not logs:
            st.warning("No logs found. Please run the analysis first.")
        else:
            # Display logs in expandable sections
            if 'analysis_report' in logs:
                with st.expander("Analysis Report", expanded=True):
                    st.text(logs['analysis_report'])
            
            # Add download button for logs
            if logs:
                combined_logs = "\n\n".join(logs.values())
                st.download_button(
                    "Download All Logs",
                    combined_logs,
                    "vulnerability_analysis_logs.txt",
                    "text/plain"
                )
    
    elif page == "Analysis Report":
        st.title("Detailed Analysis Report")
        
        # Load the latest analysis report
        report_files = glob.glob('analysis_results/*.txt')
        if report_files:
            latest_report = max(report_files, key=os.path.getctime)
            with open(latest_report, 'r') as f:
                report_content = f.read()
            
            # Display report sections
            sections = report_content.split('\n\n')
            for section in sections:
                if section.strip():
                    # Create expandable sections for each part of the report
                    header = section.split('\n')[0]
                    with st.expander(header, expanded=True):
                        st.text(section)
            
            # Add download button for report
            st.download_button(
                "Download Full Report",
                report_content,
                "vulnerability_analysis_report.txt",
                "text/plain"
            )
        else:
            st.warning("No analysis reports found. Please run the analysis first.")

    # Add this after your existing tabs
    if "GitHub Scanner" not in st.session_state:
        st.session_state["GitHub Scanner"] = False

    # Add this to your tab selection
    tab1, tab2, tab3, tab4, tab5 = st.tabs(["Dashboard", "Vulnerabilities", "Dependencies", "Logs", "GitHub Scanner"])

    # Add this under your tabs section (after the Logs tab)
    with tab5:
        st.header("GitHub Repository Scanner with Syft SBOM Analysis")
        
        st.markdown("""
        This scanner uses **Syft** - a powerful Software Bill of Materials (SBOM) generation tool that:
        - 📦 Identifies packages and dependencies in repositories
        - 🔍 Supports multiple package managers and languages
        - 🛡️ Detects potential security vulnerabilities
        - 📊 Provides detailed dependency analysis
        """)
        
        col1, col2 = st.columns([3, 1])
        with col1:
            github_url = st.text_input("GitHub Repository URL", 
                                    placeholder="https://github.com/username/repository")
        with col2:
            scan_type = st.selectbox("Scan Type", ["Full Analysis (Syft + AI)", "Quick Scan (Syft Only)"])
        
        # Add Syft configuration options
        with st.expander("🔧 Syft Scan Configuration"):
            st.markdown("""
            **Syft Capabilities:**
            - Container Image Analysis
            - Source Code Analysis
            - Package Manager Support:
              - npm/yarn (JavaScript)
              - pip/poetry (Python)
              - gem (Ruby)
              - go modules (Golang)
              - and many more!
            
            Syft will automatically detect and analyze the appropriate package managers based on your repository content.
            """)
        
        if st.button("Start Analysis"):
            if not github_url:
                st.error("Please enter a GitHub repository URL")
            else:
                with st.spinner('Analyzing repository with Syft...'):
                    try:
                        # Rest of the code remains the same until the results display
                        response = requests.post('http://localhost:5001/api/analyze', 
                                              json={'github_url': github_url})
                        
                        if response.status_code != 200:
                            st.error(f"Analysis failed: {response.json().get('error', 'Unknown error')}")
                            return
                            
                        # Poll for results
                        progress_text = st.empty()
                        while True:
                            status_response = requests.get('http://localhost:5001/api/status')
                            status_data = status_response.json()
                            
                            if status_data['status'] == 'error':
                                st.error(f"Analysis failed: {status_data.get('error', 'Unknown error')}")
                                break
                            elif status_data['status'] == 'processing':
                                progress_text.text("🔄 Syft is analyzing dependencies and generating SBOM...")
                            elif status_data['status'] == 'complete':
                                progress_text.empty()
                                
                                # Process predictions and Syft results
                                predictions = status_data.get('predictions', [])
                                syft_results = status_data.get('syft_scan', {})
                                
                                # Create tabs for different result sections
                                results_tab1, results_tab2 = st.tabs(["📊 Vulnerability Summary", "📦 Syft SBOM Analysis"])
                                
                                with results_tab1:
                                    # Display vulnerability summary
                                    total_vulnerabilities = len(predictions)
                                    severity_counts = {}
                                    for pred in predictions:
                                        severity = pred['Predicted_Severity']
                                        severity_counts[severity] = severity_counts.get(severity, 0) + 1
                                    
                                    # Calculate risk levels and display results
                                    # ... (rest of the vulnerability display code remains the same)
                                
                                with results_tab2:
                                    st.subheader("Syft Software Bill of Materials (SBOM)")
                                    if syft_results and 'artifacts' in syft_results:
                                        packages = syft_results['artifacts']
                                        
                                        # Summary metrics
                                        col1, col2, col3 = st.columns(3)
                                        with col1:
                                            st.metric("Total Packages", len(packages))
                                        with col2:
                                            vulnerable_count = sum(1 for p in packages if p.get('vulnerabilities'))
                                            st.metric("Vulnerable Packages", vulnerable_count)
                                        with col3:
                                            safe_count = len(packages) - vulnerable_count
                                            st.metric("Safe Packages", safe_count)
                                        
                                        # Package list with filtering
                                        st.markdown("### 📦 Detected Packages")
                                        filter_type = st.selectbox(
                                            "Filter packages by:",
                                            ["All", "Vulnerable Only", "Safe Only"]
                                        )
                                        
                                        for package in packages:
                                            has_vulns = bool(package.get('vulnerabilities'))
                                            if (filter_type == "All" or 
                                                (filter_type == "Vulnerable Only" and has_vulns) or
                                                (filter_type == "Safe Only" and not has_vulns)):
                                                
                                                with st.expander(f"📦 {package.get('name')} {package.get('version')}"):
                                                    st.markdown(f"""
                                                    - **Type:** {package.get('type', 'N/A')}
                                                    - **Language:** {package.get('language', 'N/A')}
                                                    - **License:** {package.get('licenses', ['N/A'])[0]}
                                                    """)
                                                    
                                                    if has_vulns:
                                                        st.markdown("#### 🔴 Vulnerabilities:")
                                                        for vuln in package['vulnerabilities']:
                                                            st.markdown(f"""
                                                            - **{vuln.get('id')}**
                                                              - Severity: {vuln.get('severity', 'N/A')}
                                                              - {vuln.get('description')}
                                                            """)
                                break
                            
                            time.sleep(1)
                            
                    except Exception as e:
                        st.error(f"Analysis failed: {str(e)}")
                        logger.error(f"Analysis failed: {str(e)}")
        
        st.markdown("---")
        st.markdown("""
        ### About Syft SBOM Analysis
        
        **Syft** is an industry-standard SBOM (Software Bill of Materials) generator that provides:
        
        1. **Comprehensive Package Detection:**
           - Identifies dependencies across multiple ecosystems
           - Supports various package managers and languages
           - Deep container image analysis
        
        2. **Detailed Package Information:**
           - Package versions and licenses
           - Dependency relationships
           - Vulnerability detection
        
        3. **Security Features:**
           - Integration with vulnerability databases
           - License compliance checking
           - Supply chain security insights
        
        4. **Output Formats:**
           - JSON for programmatic analysis
           - SPDX for standardization
           - CycloneDX for security tools
        
        The scanner combines Syft's SBOM generation with AI-powered vulnerability analysis for comprehensive security assessment.
        """)

if __name__ == "__main__":
    main()
