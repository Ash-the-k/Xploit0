import requests
import csv
import time
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

NVD_API_KEY = "02586fa2-ed24-4dbb-bdb8-782288531511"

def fetch_cve_data(package_name):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {
        "User-Agent": "Xploit0-Security-Scanner",
        "apiKey": NVD_API_KEY
    }
    
    all_cves = []
    start_index = 0
    
    while True:
        params = {
            "keywordSearch": package_name,
            "resultsPerPage": 100,  # Max allowed per request
            "startIndex": start_index
        }
        
        try:
            time.sleep(1)  # Rate limiting
            response = requests.get(url, headers=headers, params=params)
            
            if response.status_code != 200:
                print(f"Error fetching data: {response.status_code}")
                break
            
            data = response.json()
            vulns = data.get("vulnerabilities", [])
            
            if not vulns:  # No more results
                break
            
            for item in vulns:
                cve = item.get("cve", {})
                cve_id = cve.get("id", "N/A")
                description = cve.get("descriptions", [{}])[0].get("value", "N/A")
                metrics = cve.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {})
                cvss_score = metrics.get("baseScore", "N/A")
                severity = metrics.get("baseSeverity", "N/A")
                
                all_cves.append([cve_id, package_name, cvss_score, severity, description])
            
            # Show progress
            print(f"Fetched {len(all_cves)} vulnerabilities so far...")
            
            # Check if we've got all results
            total_results = data.get("totalResults", 0)
            if start_index + len(vulns) >= total_results:
                break
                
            start_index += len(vulns)
            
        except Exception as e:
            print(f"Error processing {package_name}: {str(e)}")
            break
    
    return all_cves

def save_to_csv(cve_data, filename="cve_data.csv"):
    with open(filename, "w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["CVE_ID", "Package", "CVSS", "Severity", "Description"])
        writer.writerows(cve_data)
    print(f"Saved to {filename}")

def prepare_training_data(cve_data):
    """Prepare CVE data for model training."""
    if not cve_data:
        print("No data available for training")
        return None, None, None, None
    
    # Convert to DataFrame
    df = pd.DataFrame(cve_data, columns=["CVE_ID", "Package", "CVSS", "Severity", "Description"])
    
    # Convert CVSS to numeric, handling 'N/A' values
    df['CVSS'] = pd.to_numeric(df['CVSS'].replace('N/A', np.nan))
    df['CVSS'] = df['CVSS'].fillna(df['CVSS'].mean())
    
    # Encode severity levels
    le = LabelEncoder()
    df['Severity'] = le.fit_transform(df['Severity'].fillna('UNKNOWN'))
    
    # Prepare features (X) and target (y)
    X = df[['CVSS']].values  # You can add more features here
    y = df['Severity'].values
    
    # Split the data
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    print("Data preparation completed:")
    print(f"Training samples: {len(X_train)}")
    print(f"Testing samples: {len(X_test)}")
    
    return X_train, X_test, y_train, y_test

if __name__ == "__main__":
    packages = ["tensorflow", "django", "flask", "numpy"]
    all_cve_data = []
    
    for package in packages:
        print(f"\nFetching CVEs for {package}...")
        cve_data = fetch_cve_data(package)
        if cve_data:
            print(f"Found {len(cve_data)} vulnerabilities for {package}")
            all_cve_data.extend(cve_data)
        else:
            print(f"No vulnerabilities found for {package}")
    
    if all_cve_data:
        # Save raw data
        save_to_csv(all_cve_data)
        print(f"\nTotal vulnerabilities found: {len(all_cve_data)}")
        
        # Prepare data for training
        X_train, X_test, y_train, y_test = prepare_training_data(all_cve_data)
        
        # Save training data to separate files
        if X_train is not None:
            np.save('X_train.npy', X_train)
            np.save('X_test.npy', X_test)
            np.save('y_train.npy', y_train)
            np.save('y_test.npy', y_test)
            print("\nTraining data saved to .npy files")
    else:
        print("\nNo vulnerabilities found for any package")
