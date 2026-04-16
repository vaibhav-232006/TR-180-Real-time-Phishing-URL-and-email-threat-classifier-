import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.preprocessing import LabelEncoder
import joblib

# 1. Load the Dataset
print("Loading dataset...")
df = pd.read_csv("phishing_dataset.csv")

# Strip leading/trailing spaces from column names
df.columns = df.columns.str.strip()

# 2. Define Features (X) and Target (y)
features = [
    'Flow Duration',
    'Total Fwd Packets',
    'Total Backward Packets',
    'Average Packet Size',
    'Fwd Packet Length Max',
    'Bwd Packet Length Max',
    'Packet Length Mean',
    'Packet Length Std'
]

# 3. Clean infinite and null values
print("Cleaning data...")
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(subset=features + ['Label'], inplace=True)

# 4. Encode the Label column (BENIGN, DDoS, etc. → 0, 1, 2...)
le = LabelEncoder()
y = le.fit_transform(df['Label'])
X = df[features]

print(f"Classes found: {le.classes_}")
print(f"Dataset shape: {X.shape}")

# 5. Split the Data
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# 6. Train the Model
print("Training the Random Forest model (this might take a minute)...")
model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
model.fit(X_train, y_train)

# 7. Evaluate the Model
print("Evaluating model performance...")
predictions = model.predict(X_test)
accuracy = accuracy_score(y_test, predictions)

print(f"\nModel Accuracy: {accuracy * 100:.2f}%")
print("\nDetailed Report:")
print(classification_report(y_test, predictions, target_names=le.classes_))

# 8. Save the Model and Label Encoder
print("Saving the trained model...")
joblib.dump(model, "phishing_model.pkl")
joblib.dump(le, "label_encoder.pkl")
print("Done! Model saved as 'phishing_model.pkl'.")