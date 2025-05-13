import requests
import csv
import time
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
import os
import json
from packaging import requirements

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
            "resultsPerPage": 100,
            "startIndex": start_index
        }

        try:
            time.sleep(1)  # Respect rate limits
            response = requests.get(url, headers=headers, params=params)

            if response.status_code != 200:
                print(f"Error fetching data for {package_name}: {response.status_code}")
                break

            data = response.json()
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                break

            for item in vulns:
                cve = item.get("cve", {})
                cve_id = cve.get("id", "N/A")
                description = cve.get("descriptions", [{}])[0].get("value", "N/A")
                metrics = cve.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {})
                cvss_score = metrics.get("baseScore", "N/A")
                severity = metrics.get("baseSeverity", "N/A")

                all_cves.append([cve_id, package_name, cvss_score, severity, description])

            print(f"Fetched {len(all_cves)} vulnerabilities so far...")

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
    if not cve_data:
        print("No data available for training")
        return None, None, None, None

    df = pd.DataFrame(cve_data, columns=["CVE_ID", "Package", "CVSS", "Severity", "Description"])

    df['CVSS'] = pd.to_numeric(df['CVSS'].replace('N/A', np.nan))
    df['CVSS'] = df['CVSS'].fillna(df['CVSS'].mean())

    le = LabelEncoder()
    df['Severity'] = le.fit_transform(df['Severity'].fillna('UNKNOWN'))

    X = df[['CVSS']].values
    y = df['Severity'].values

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    print("Data preparation completed:")
    print(f"Training samples: {len(X_train)}")
    print(f"Testing samples: {len(X_test)}")

    return X_train, X_test, y_train, y_test

def get_packages_from_requirements(file_path="requirements.txt"):
    packages = []
    if not os.path.exists(file_path):
        print("[!] requirements.txt not found")
        return packages
    with open(file_path, 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                try:
                    req = requirements.Requirement(line)
                    packages.append(req.name)
                except Exception as e:
                    print(f"[!] Skipping invalid line: {line} ({e})")
    return packages

def get_packages_from_packages_json(file_path="packages.json"):
    packages = []
    if not os.path.exists(file_path):
        print("[!] packages.json not found")
        return packages
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
            for pkg in data.get("packages", []):
                if isinstance(pkg, list) and len(pkg) == 2:
                    packages.append(pkg[0])
    except Exception as e:
        print(f"[!] Error reading packages.json: {str(e)}")
    return packages

if __name__ == "__main__":
    # Collect packages from both files
    packages = set()

    reqs = get_packages_from_requirements()
    pkgs = get_packages_from_packages_json()

    packages.update(reqs)
    packages.update(pkgs)

    if not packages:
        print("[!] No valid packages found in requirements.txt or packages.json.")
        exit()

    all_cve_data = []

    for package in sorted(packages):
        print(f"\nFetching CVEs for {package}...")
        cve_data = fetch_cve_data(package)
        if cve_data:
            print(f"Found {len(cve_data)} vulnerabilities for {package}")
            all_cve_data.extend(cve_data)
        else:
            print(f"No vulnerabilities found for {package}")

    if all_cve_data:
        save_to_csv(all_cve_data)
        print(f"\nTotal vulnerabilities found: {len(all_cve_data)}")

        X_train, X_test, y_train, y_test = prepare_training_data(all_cve_data)
        if X_train is not None:
            np.save('X_train.npy', X_train)
            np.save('X_test.npy', X_test)
            np.save('y_train.npy', y_train)
            np.save('y_test.npy', y_test)
            print("\nTraining data saved to .npy files")
    else:
        print("\nNo vulnerabilities found for any package.")
