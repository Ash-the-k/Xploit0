import pandas as pd
import numpy as np
import joblib
from sklearn.preprocessing import StandardScaler
from sklearn.feature_extraction.text import TfidfVectorizer
import argparse
import os
from datetime import datetime

def get_recommendation(row):
    """Generate recommendations based on severity and CVSS score"""
    severity = row['Predicted_Severity']
    package = row['Package']
    cvss = row['CVSS']
    
    if severity == 'CRITICAL':
        return f"URGENT: Immediate update required for {package}. CVSS Score {cvss:.1f} indicates critical security risk."
    elif severity == 'HIGH':
        return f"Important: Update {package} as soon as possible. High security risk (CVSS: {cvss:.1f})."
    elif severity == 'MEDIUM':
        return f"Moderate: Plan to update {package} in next maintenance window. (CVSS: {cvss:.1f})"
    else:  # LOW
        return f"Low priority: Monitor {package} for updates. Current risk is low. (CVSS: {cvss:.1f})"

def preprocess_new_data(df):
    """Preprocess new data for prediction"""
    # Load preprocessing objects
    preprocessing_objects = joblib.load('preprocessing_objects.joblib')
    tfidf = preprocessing_objects['tfidf']
    scaler = preprocessing_objects['scaler']
    
    # Handle missing values in CVSS
    df['CVSS'] = pd.to_numeric(df['CVSS'].replace('N/A', np.nan))
    df['CVSS'] = df['CVSS'].fillna(df['CVSS'].mean())
    
    # Create text features using saved TF-IDF
    description_features = tfidf.transform(df['Description'].fillna(''))
    
    # Create basic numeric features
    df['Description_Length'] = df['Description'].str.len()
    df['Has_RCE'] = df['Description'].str.contains('remote|execution|code', case=False).astype(int)
    df['Has_DOS'] = df['Description'].str.contains('denial|service|dos', case=False).astype(int)
    df['Has_Overflow'] = df['Description'].str.contains('overflow|buffer|stack', case=False).astype(int)
    
    # Combine features
    numeric_features = ['CVSS', 'Description_Length', 'Has_RCE', 'Has_DOS', 'Has_Overflow']
    X_numeric = df[numeric_features].values
    X_text = description_features.toarray()
    
    # Combine numeric and text features
    X = np.hstack((X_numeric, X_text))
    
    # Scale numeric features using saved scaler
    X[:, :len(numeric_features)] = scaler.transform(X[:, :len(numeric_features)])
    
    return X

def generate_summary_report(results_df, output_dir):
    """Generate a detailed summary report"""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    report_file = os.path.join(output_dir, f'vulnerability_report_{timestamp}.txt')
    
    with open(report_file, 'w') as f:
        f.write("Vulnerability Analysis Report\n")
        f.write("=" * 30 + "\n\n")
        
        # Overall statistics
        f.write("Overall Statistics:\n")
        f.write("-" * 20 + "\n")
        severity_counts = results_df['Predicted_Severity'].value_counts()
        for severity, count in severity_counts.items():
            f.write(f"{severity}: {count} vulnerabilities\n")
        f.write("\n")
        
        # Package-wise summary
        f.write("Package-wise Summary:\n")
        f.write("-" * 20 + "\n")
        for package in results_df['Package'].unique():
            pkg_data = results_df[results_df['Package'] == package]
            f.write(f"\nPackage: {package}\n")
            
            # Count vulnerabilities by severity for this package
            severity_counts = pkg_data['Predicted_Severity'].value_counts()
            for severity, count in severity_counts.items():
                f.write(f"- {severity}: {count} vulnerabilities\n")
            
            # List critical and high vulnerabilities
            critical_high = pkg_data[pkg_data['Predicted_Severity'].isin(['CRITICAL', 'HIGH'])]
            if not critical_high.empty:
                f.write("\nCritical/High Vulnerabilities:\n")
                for _, row in critical_high.iterrows():
                    f.write(f"  * {row['CVE_ID']} (Severity: {row['Predicted_Severity']})\n")
                    f.write(f"    Recommendation: {row['Recommendation']}\n")
            f.write("\n")
    
    return report_file

def predict_vulnerabilities(args):
    try:
        # Create output directory if it doesn't exist
        os.makedirs(args.output_dir, exist_ok=True)
        
        # Check if model exists
        if not os.path.exists(args.model):
            print(f"Error: Model file {args.model} not found. Please run modeltrain.py first.")
            return None
            
        # Load the trained model
        print("Loading model...")
        model = joblib.load(args.model)
        
        # Check if input file exists
        if not os.path.exists(args.input):
            print(f"Error: Could not find input file {args.input}")
            return None
            
        # Load and preprocess new data
        print(f"Loading data from {args.input}...")
        df = pd.read_csv(args.input)
        print(f"Found {len(df)} vulnerabilities to analyze")
        
        # Preprocess the data
        print("Preprocessing data...")
        X = preprocess_new_data(df)
        
        # Make predictions
        print("Making predictions...")
        y_pred = model.predict(X)
        
        # Map predictions to severity labels
        severity_map = {0: 'LOW', 1: 'MEDIUM', 2: 'HIGH', 3: 'CRITICAL'}
        predictions = [severity_map[pred] for pred in y_pred]
        
        # Create results DataFrame
        results_df = pd.DataFrame({
            'CVE_ID': df['CVE_ID'],
            'Package': df['Package'],
            'Description': df['Description'],
            'CVSS': df['CVSS'],
            'Predicted_Severity': predictions
        })
        
        # Add recommendations
        print("Generating recommendations...")
        results_df['Recommendation'] = results_df.apply(get_recommendation, axis=1)
        
        # Save predictions
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        predictions_file = os.path.join(args.output_dir, f'predictions_{timestamp}.csv')
        results_df.to_csv(predictions_file, index=False)
        print(f"\nPredictions saved to {predictions_file}")
        
        # Generate and save detailed report
        print("Generating detailed report...")
        report_file = generate_summary_report(results_df, args.output_dir)
        print(f"Detailed report saved to {report_file}")
        
        # Print summary statistics
        print("\nPrediction Summary:")
        summary = results_df['Predicted_Severity'].value_counts()
        print(summary)
        
        # Print sample predictions
        print("\nSample Predictions:")
        sample = results_df[['CVE_ID', 'Package', 'CVSS', 'Predicted_Severity', 'Recommendation']].head(5)
        print(sample.to_string(index=False))
        
        return results_df
        
    except Exception as e:
        print(f"Error during prediction: {str(e)}")
        return None

def main():
    parser = argparse.ArgumentParser(description="Predict vulnerability severity and generate recommendations.")
    parser.add_argument("--input", default="cve_data.csv", help="Path to input CSV file")
    parser.add_argument("--model", default="trained_model.joblib", help="Path to trained model file")
    parser.add_argument("--output-dir", default="vulnerability_reports", help="Directory for output files")
    args = parser.parse_args()
    
    predict_vulnerabilities(args)

if __name__ == "__main__":
    main()