# train_model.py
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
import joblib # A tool for saving/loading models
import sys # To check for errors

print("--- Starting AI Model Training ---")

# Step 1: Load the dataset
try:
    df = pd.read_csv('packages_dataset.csv')
    print("Dataset 'packages_dataset.csv' loaded successfully.")
except FileNotFoundError:
    print("!!! ERROR: 'packages_dataset.csv' not found.")
    print("Please create it first.")
    sys.exit() # Exit the script if file not found

# Step 2: Prepare data for training
# These are the "clues" our AI will use
feature_columns = [
    'has_author', 'has_homepage', 'github_followers',
    'github_account_age_days', 'package_age_days', 'num_versions',
    'has_dangerous_code'
]
# This is the "answer" it needs to learn
target_column = 'is_risky'

X = df[feature_columns] # The features (clues)
y = df[target_column]   # The target (answer)

# Split data: 80% for training, 20% for testing
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
print("Data prepared and split for training.")

# Step 3: Train the AI Model
# We're using a "Random Forest," which is like a team of decision-makers
model = RandomForestClassifier(n_estimators=100, random_state=42)

print("Training the Random Forest model...")
model.fit(X_train, y_train)
print("Model training complete!")

# Step 4: Check how well the model learned
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f"\nModel Accuracy on test data: {accuracy * 100:.2f}%")
if accuracy < 1.0:
    print("Note: Accuracy is less than 100%. This is normal on larger datasets.")

# Step 5: Save the trained "brain" to a file
model_filename = 'codesentinel_model.pkl'
joblib.dump(model, model_filename)

print(f"\n--- Success! Model saved as '{model_filename}' ---")