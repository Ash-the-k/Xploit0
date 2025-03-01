import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import cross_val_score, train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.preprocessing import StandardScaler
from sklearn.feature_extraction.text import TfidfVectorizer
import matplotlib.pyplot as plt
import seaborn as sns
import joblib

# Load and preprocess the data
def preprocess_data(df):
    print("\nInitial data shape:", df.shape)
    print("\nInitial severity distribution:")
    print(df['Severity'].value_counts(dropna=False))
    
    # Clean severity values first
    df['Severity'] = df['Severity'].str.upper()
    df['Severity'] = df['Severity'].replace('N/A', np.nan)
    
    # Map severity to numeric values
    severity_map = {
        'LOW': 0,
        'MEDIUM': 1,
        'HIGH': 2,
        'CRITICAL': 3
    }
    
    # Filter rows with valid severity values first
    df = df[df['Severity'].isin(severity_map.keys())].copy()  # Use .copy() to avoid SettingWithCopyWarning
    
    # Handle missing values in CVSS
    df['CVSS'] = pd.to_numeric(df['CVSS'].replace('N/A', np.nan))
    df['CVSS'] = df['CVSS'].fillna(df['CVSS'].mean())
    
    # Create text features using TF-IDF
    tfidf = TfidfVectorizer(max_features=100, stop_words='english')
    description_features = tfidf.fit_transform(df['Description'].fillna(''))
    
    # Create basic numeric features
    df['Description_Length'] = df['Description'].str.len()
    df['Has_RCE'] = df['Description'].str.contains('remote|execution|code', case=False).astype(int)
    df['Has_DOS'] = df['Description'].str.contains('denial|service|dos', case=False).astype(int)
    df['Has_Overflow'] = df['Description'].str.contains('overflow|buffer|stack', case=False).astype(int)
    
    # Convert severity to numeric
    df['Severity_Numeric'] = df['Severity'].map(severity_map)
    
    # Combine all features
    numeric_features = ['CVSS', 'Description_Length', 'Has_RCE', 'Has_DOS', 'Has_Overflow']
    X_numeric = df[numeric_features].values
    X_text = description_features.toarray()
    
    # Combine numeric and text features
    X = np.hstack((X_numeric, X_text))
    y = df['Severity_Numeric'].values
    
    # Scale numeric features
    scaler = StandardScaler()
    X[:, :len(numeric_features)] = scaler.fit_transform(X[:, :len(numeric_features)])
    
    feature_names = numeric_features + [f'text_feature_{i}' for i in range(X_text.shape[1])]
    
    print("\nFinal data shape:", X.shape)
    print("Final severity distribution:")
    print(df['Severity'].value_counts())
    
    # Store original data for later reference
    metadata = df[['CVE_ID', 'Package', 'Severity']].copy()
    
    return X, y, feature_names, metadata

# Load the data
df = pd.read_csv('cve_data.csv')

# Preprocess data
X, y, feature_names, metadata = preprocess_data(df)

# Verify no NaN values
print("\nChecking for NaN values:")
print("NaN in features:", np.isnan(X).any())
print("NaN in target:", np.isnan(y).any())

# Split the data
X_train, X_test, y_train, y_test, metadata_train, metadata_test = train_test_split(
    X, y, metadata, test_size=0.2, random_state=42
)

print("\nTraining data shape:", X_train.shape)
print("Testing data shape:", X_test.shape)

# Train the model
model = RandomForestClassifier(n_estimators=200, max_depth=10, random_state=42)
model.fit(X_train, y_train)

# Cross-validation
cv_scores = cross_val_score(model, X, y, cv=5)
print("\nCross-validation scores:", cv_scores)
print("Average CV score: {:.2f} (+/- {:.2f})".format(cv_scores.mean(), cv_scores.std() * 2))

# Make predictions
y_pred = model.predict(X_test)

# Create a DataFrame for predictions
predictions_df = pd.DataFrame({
    "CVE_ID": metadata_test['CVE_ID'],
    "Package": metadata_test['Package'],
    "Actual_Severity": metadata_test['Severity'],
    "Predicted_Severity": [['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'][pred] for pred in y_pred]
})

# Print detailed results
print("\nModel Evaluation:")
print(f"Accuracy: {accuracy_score(y_test, y_pred):.2f}")

print("\nClassification Report:")
print(classification_report(y_test, y_pred, 
                          target_names=['Low', 'Medium', 'High', 'Critical']))

# Plot confusion matrix
plt.figure(figsize=(10,8))
cm = confusion_matrix(y_test, y_pred)
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
            xticklabels=['Low', 'Medium', 'High', 'Critical'],
            yticklabels=['Low', 'Medium', 'High', 'Critical'])
plt.title('Confusion Matrix')
plt.ylabel('True Label')
plt.xlabel('Predicted Label')
plt.savefig('confusion_matrix.png')
plt.close()

# Feature importance
importances = model.feature_importances_
indices = np.argsort(importances)[::-1]

print("\nTop 10 Most Important Features:")
for f in range(min(10, len(feature_names))):
    print("%d. %s (%f)" % (f + 1, feature_names[indices[f]], importances[indices[f]]))

# Plot feature importance (top 10)
plt.figure(figsize=(12,6))
plt.title("Top 10 Feature Importances")
top_features = 10
plt.bar(range(top_features), importances[indices[:top_features]])
plt.xticks(range(top_features), [feature_names[i] for i in indices[:top_features]], rotation=45, ha='right')
plt.tight_layout()
plt.savefig('feature_importance.png')
plt.close()

# Print example predictions with context
print("\nExample Predictions with Context:")
print("\nSample of Predictions:")
print(predictions_df.head(10).to_string(index=False))

# Save predictions to CSV
predictions_file = "vulnerability_predictions.csv"
predictions_df.to_csv(predictions_file, index=False)
print(f"\nAll predictions saved to {predictions_file}")

# Print misclassified examples
print("\nMisclassified Examples:")
misclassified = predictions_df[predictions_df['Actual_Severity'] != predictions_df['Predicted_Severity']]
if len(misclassified) > 0:
    print(misclassified.head(5).to_string(index=False))
    print(f"\nTotal misclassified: {len(misclassified)} out of {len(predictions_df)} ({len(misclassified)/len(predictions_df)*100:.2f}%)")
else:
    print("No misclassified examples found!")

# Save the trained model
model_file = "trained_model.joblib"
joblib.dump(model, model_file)
print(f"\nModel saved to {model_file}")