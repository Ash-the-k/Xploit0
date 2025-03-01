import requests
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
import joblib
from rich.console import Console
from rich.table import Table

# Initialize Rich console
console = Console()

# Step 1: Fetch CVE Data
def fetch_cve_data(package_name, version):
    query = {
        "package": {"name": package_name, "ecosystem": "PyPI"},
        "version": version,
    }
    response = requests.post("https://api.osv.dev/v1/query", json=query)
    if response.status_code == 200:
        return response.json()
    return None

# Step 2: Extract Features
def extract_features(cve_data):
    """
    Extract relevant features from CVE data for ML analysis.
    """
    features = []
    for vuln in cve_data.get("vulns", []):
        try:
            # Get severity details
            severity_details = vuln.get("severity", [])
            severity_score = 0.0
            
            # Try different severity formats
            if severity_details:
                if isinstance(severity_details, list):
                    for detail in severity_details:
                        if isinstance(detail, dict) and 'score' in detail:
                            try:
                                severity_score = float(detail['score'])
                                break
                            except (ValueError, TypeError):
                                continue
                elif isinstance(severity_details, dict) and 'score' in severity_details:
                    try:
                        severity_score = float(severity_details['score'])
                    except (ValueError, TypeError):
                        pass

            # Calculate additional risk factors
            affected = vuln.get("affected", [])
            references = vuln.get("references", [])
            modified_date = vuln.get("modified", "")
            
            # Calculate risk level based on multiple factors
            risk_score = severity_score
            if len(affected) > 3:  # Many versions affected
                risk_score += 1
            if len(references) > 5:  # Many references usually indicate serious issues
                risk_score += 1
            if "critical" in str(vuln).lower():
                risk_score += 2

            # Determine risk level
            if risk_score >= 8:
                risk_level = "Critical"
            elif risk_score >= 6:
                risk_level = "High"
            elif risk_score >= 4:
                risk_level = "Medium"
            else:
                risk_level = "Low"

            features.append({
                "severity": severity_score,
                "risk_level": risk_level,
                "affected_versions": len(affected),
                "references": len(references),
                "has_fix": any("fix" in str(ref).lower() for ref in references),
                "is_critical": "critical" in str(vuln).lower()
            })
            
        except Exception as e:
            console.print(f"[red]Error extracting features: {str(e)}[/red]")
            continue
            
    return features

# Step 3: Train a Baseline Model
def train_model(features):
    """
    Train a machine learning model on the extracted features.
    """
    try:
        # Create DataFrame
        df = pd.DataFrame(features)
        
        if len(df) < 2:
            console.print("[red]Not enough data for training[/red]")
            return None
            
        # Prepare features
        X = df[["severity", "affected_versions", "references"]]
        y = df["risk_level"]
        
        # Use stratified split to handle imbalanced classes
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y if len(set(y)) > 1 else None
        )
        
        # Initialize model with balanced class weights
        model = RandomForestClassifier(
            n_estimators=100,
            class_weight="balanced",
            random_state=42,
            min_samples_leaf=2
        )
        
        model.fit(X_train, y_train)
        
        # Evaluate
        y_pred = model.predict(X_test)
        
        # Print evaluation results using Rich
        console.print("\n[bold]Model Evaluation:[/bold]")
        console.print(f"Accuracy: [green]{accuracy_score(y_test, y_pred):.2f}[/green]")
        
        # Print classification report as a table
        report = classification_report(y_test, y_pred, output_dict=True)
        table = Table(title="Classification Report", show_header=True, header_style="bold magenta")
        table.add_column("Class", style="cyan")
        table.add_column("Precision", style="green")
        table.add_column("Recall", style="green")
        table.add_column("F1-Score", style="green")
        table.add_column("Support", style="yellow")
        
        for cls, metrics in report.items():
            if cls not in ["accuracy", "macro avg", "weighted avg"]:
                table.add_row(
                    cls,
                    f"{metrics['precision']:.2f}",
                    f"{metrics['recall']:.2f}",
                    f"{metrics['f1-score']:.2f}",
                    str(metrics['support'])
                )
        
        console.print(table)
        
        return model
        
    except Exception as e:
        console.print(f"[red]Error in model training: {str(e)}[/red]")
        return None

# Step 4: Predict Risk Level
def predict_risk(model, features):
    """
    Predict risk level using the trained model.
    """
    try:
        # Convert features to DataFrame
        df = pd.DataFrame([features])
        
        # Prepare features for prediction
        X = df[["severity", "affected_versions", "references"]]
        
        # Make prediction
        prediction = model.predict(X)
        return prediction[0]
    
    except Exception as e:
        console.print(f"[red]Error making prediction: {str(e)}[/red]")
        return "Unknown"

# Step 5: Save and Load the Model
def save_model(model, filename):
    joblib.dump(model, filename)

def load_model(filename):
    return joblib.load(filename)

# Example Usage
if __name__ == "__main__":
    # Fetch CVE data for multiple packages
    packages = [
        ("requests", "2.28.1"),
        ("requests", "2.27.0"),
        ("requests", "2.26.0"),
        ("numpy", "1.21.0"),
        ("numpy", "1.20.0"),
        ("numpy", "1.19.0"),
        ("flask", "2.0.1"),
        ("flask", "1.1.0"),
        ("flask", "1.0.0"),
        ("pandas", "1.3.0"),
        ("pandas", "1.2.0"),
        ("pandas", "1.1.0"),
        ("tensorflow", "2.6.0"),
        ("scikit-learn", "1.0.0"),
        ("django", "3.2.0"),
        ("matplotlib", "3.4.0"),
        ("pygame", "2.0.1"),
        ("pillow", "8.3.0"),
    ]
    
    all_features = []
    for package_name, version in packages:
        cve_data = fetch_cve_data(package_name, version)
        if cve_data:
            features = extract_features(cve_data)
            all_features.extend(features)
    
    if all_features:
        # Train the model
        model = train_model(all_features)
        if model:
            # Save the trained model
            save_model(model, "risk_prediction_model.pkl")

            # Predict risk level for a new dependency
            loaded_model = load_model("risk_prediction_model.pkl")
            new_features = {
                "severity": 7.5,
                "affected_versions": 2,
                "references": 1,
            }
            predicted_risk = predict_risk(loaded_model, new_features)
            console.print(f"\n[bold]Predicted Risk Level:[/bold] [green]{predicted_risk}[/green]")
    else:
        console.print("[red]No features extracted from CVE data.[/red]")