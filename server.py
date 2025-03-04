from flask import Flask, jsonify, request
from flask_cors import CORS
import os
import time
import json
import random
import logging
import re
import subprocess
import shutil
import threading

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__, static_folder='.', static_url_path='')

# Configure CORS to allow all origins
CORS(app, resources={
    r"/api/*": {
        "origins": "*",
        "methods": ["GET", "POST", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"]
    }
})

# Store scan status and results
scan_status = {
    'status': 'idle',
    'predictions': [],
    'error': None
}

@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response

def validate_github_url(url):
    """Validate and format GitHub URL"""
    # Remove trailing slashes and .git extension
    url = url.strip().rstrip('/')
    if url.endswith('.git'):
        url = url[:-4]
    
    # Check if it's a valid GitHub URL
    github_pattern = r'^https?://github\.com/[\w-]+/[\w.-]+$'
    if not re.match(github_pattern, url):
        raise ValueError('Invalid GitHub URL format. Please use: https://github.com/username/repository')
    
    # Add .git extension for cloning
    return f"{url}.git"

def clone_repository(github_url):
    """Clone the repository and return the local path"""
    try:
        # Validate and format the URL
        github_url = validate_github_url(github_url)
        logger.info(f"Validated GitHub URL: {github_url}")
        
        repo_name = github_url.split('/')[-1]
        if repo_name.endswith('.git'):
            repo_name = repo_name[:-4]
        
        base_path = os.path.abspath('./repos')
        local_path = os.path.join(base_path, repo_name)
        logger.info(f"Local path for cloning: {local_path}")
        
        # Remove existing repo if it exists
        if os.path.exists(local_path):
            logger.info(f"Removing existing repository at {local_path}")
            shutil.rmtree(local_path, ignore_errors=True)
            time.sleep(1)  # Give the system time to complete the deletion
        
        # Create parent directory if it doesn't exist
        os.makedirs(base_path, exist_ok=True)
        
        # First try to check if git is available
        try:
            subprocess.run(['git', '--version'], check=True, capture_output=True)
        except subprocess.CalledProcessError:
            raise Exception("Git is not installed or not accessible")
        
        # Clone the repository
        process = subprocess.run(
            ['git', 'clone', github_url, local_path],
            capture_output=True,
            text=True,
            check=False
        )
        
        if process.returncode != 0:
            error_msg = process.stderr or process.stdout or f"Git clone failed with exit code {process.returncode}"
            raise Exception(error_msg)
        
        # Verify the repository was cloned
        if not os.path.exists(os.path.join(local_path, '.git')):
            raise Exception("Repository was not cloned properly")
        
        logger.info("Repository cloned successfully")
        return local_path
    
    except Exception as e:
        logger.error(f"Error in clone_repository: {str(e)}")
        raise Exception(f"Failed to clone repository: {str(e)}")

def analyze_repository(local_path):
    """Simulate repository analysis"""
    try:
        logger.info(f"Starting repository analysis at {local_path}")
        
        # This is a mock analysis - replace with your actual analysis logic
        severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        packages = ['react', 'lodash', 'express', 'moment', 'axios']
        
        predictions = []
        num_vulnerabilities = random.randint(5, 15)
        logger.info(f"Generating {num_vulnerabilities} mock vulnerabilities")
        
        for i in range(num_vulnerabilities):
            severity = random.choice(severities)
            predictions.append({
                'CVE_ID': f'CVE-2023-{random.randint(1000, 9999)}',
                'Package': random.choice(packages),
                'Predicted_Severity': severity,
                'CVSS': round(random.uniform(2.0, 9.9), 1),
                'Description': f'Mock vulnerability description for testing purposes.',
                'Recommendation': 'Update to the latest version of the package.'
            })
        
        logger.info("Analysis completed successfully")
        return predictions
    
    except Exception as e:
        logger.error(f"Error in analyze_repository: {str(e)}")
        raise

@app.route('/')
def serve_index():
    return app.send_static_file('index.html')

@app.route('/api/analyze', methods=['POST'])
def start_analysis():
    try:
        data = request.json
        github_url = data.get('github_url')
        logger.info(f"Received analysis request for URL: {github_url}")
        
        if not github_url:
            logger.error("No GitHub URL provided")
            return jsonify({'error': 'GitHub URL is required'}), 400
        
        # Update status to processing
        scan_status['status'] = 'processing'
        logger.info("Status updated to processing")
        
        # Clone repository
        local_path = clone_repository(github_url)
        logger.info(f"Repository cloned to {local_path}")
        
        # Simulate some processing time
        time.sleep(2)
        
        # Analyze repository
        predictions = analyze_repository(local_path)
        
        # Update status and store results
        scan_status['status'] = 'complete'
        scan_status['predictions'] = predictions
        logger.info("Analysis completed and results stored")
        
        return jsonify({'message': 'Analysis started successfully'}), 200
    
    except ValueError as e:
        logger.error(f"Validation error: {str(e)}")
        scan_status['status'] = 'error'
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        logger.error(f"Error in start_analysis: {str(e)}")
        scan_status['status'] = 'error'
        return jsonify({'error': str(e)}), 500

@app.route('/api/status', methods=['GET'])
def get_status():
    return jsonify(scan_status)

def start_streamlit():
    """Start the Streamlit dashboard in a separate process"""
    subprocess.Popen(['streamlit', 'run', 'dashboard.py'], 
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE)

if __name__ == '__main__':
    # Start Streamlit in a separate thread
    threading.Thread(target=start_streamlit, daemon=True).start()
    
    # Create repos directory if it doesn't exist
    if not os.path.exists('./repos'):
        os.makedirs('./repos')
    
    # Start Flask server
    logger.info("Starting Flask server on port 5001")
    app.run(host='0.0.0.0', port=5001, debug=True) 