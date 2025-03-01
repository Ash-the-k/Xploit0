import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split

# Load the dataset
df = pd.read_csv("cve_data.csv")

# Convert Severity to numerical values
severity_map = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
df["Severity"] = df["Severity"].map(severity_map)

# Handle missing CVSS scores (drop rows with "N/A")
df = df[df["CVSS"] != "N/A"]

# Extract features from Description using TF-IDF
tfidf = TfidfVectorizer(max_features=1000)  # Limit to 1000 features for simplicity
description_features = tfidf.fit_transform(df["Description"])

# Combine numerical and text features
X = pd.concat([
    df[["CVSS", "Severity"]].reset_index(drop=True),
    pd.DataFrame(description_features.toarray())
], axis=1)

# Target variable (risk level)
y = df["Severity"]

# Split the data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

print("Preprocessing complete!")
print(f"Training set: {X_train.shape}, Testing set: {X_test.shape}")