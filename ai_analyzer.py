# a bridge between our  web app and our AI model.
# ai_analyzer.py
import main  # Use all our functions from main.py
import joblib
from datetime import datetime, timezone
import pandas as pd
import sys

# Load the trained model from the file
try:
    model = joblib.load('codesentinel_model.pkl')
    print("[AI Analyzer] Model 'codesentinel_model.pkl' loaded.")
except FileNotFoundError:
    print("[AI Analyzer] ERROR: 'codesentinel_model.pkl' not found.")
    model = None

def run_ai_analysis(package_name):
    """
    Gathers live data, formats it, and gets a prediction from the Al model.
    """
    if not model:
        return {"error": "AI model not loaded. Run train_model.py first."}

    # 1. Gather all the raw data using our existing functions
    print(f"[AI Analyzer] Gathering data for '{package_name}'...")
    pypi_data = main.get_package_data(package_name)
    if not pypi_data:
        return {"error": f"Could not find package '{package_name}' on PyPI."}

    info = pypi_data.get('info', {})
    releases = pypi_data.get('releases', {})
    version = info.get('version')

    # 2. Convert raw data into the numeric features our model expects
    features = {}
    
    features['has_author'] = 1 if info.get('author') else 0
    features['has_homepage'] = 1 if info.get('home_page') else 0
    features['num_versions'] = len(releases)

    # Get package age
    if releases:
        all_upload_times = []
        for v_files in releases.values():
            for file_info in v_files:
                upload_time_str = file_info.get('upload_time_iso_8601')
                if upload_time_str:
                    all_upload_times.append(datetime.fromisoformat(upload_time_str))
        if all_upload_times:
            features['package_age_days'] = (datetime.now(timezone.utc) - min(all_upload_times)).days
        else:
            features['package_age_days'] = 0
    else:
        features['package_age_days'] = 0

    # Get GitHub features
    github_username = main.extract_github_username(pypi_data)
    if github_username:
        github_info = main.get_github_user_info(github_username)
        if github_info:
            features['github_followers'] = github_info.get('followers', 0)
            created_at_date = datetime.fromisoformat(github_info.get('created_at').replace('Z', '+00:00'))
            features['github_account_age_days'] = (datetime.now(timezone.utc) - created_at_date).days
        else:
            features['github_followers'] = 0
            features['github_account_age_days'] = 0
    else:
        features['github_followers'] = 0
        features['github_account_age_days'] = 0

    # Get dangerous code feature
    code_findings = main.analyze_source_code(package_name, version)
    features['has_dangerous_code'] = 1 if code_findings else 0

    # 3. Get a prediction from the AI model
    # We need to format the features into a DataFrame in the correct order
    feature_order = [
        'has_author', 'has_homepage', 'github_followers',
        'github_account_age_days', 'package_age_days', 'num_versions',
        'has_dangerous_code'
    ]
    
    live_features_df = pd.DataFrame([features], columns=feature_order)
    
    print(f"[AI Analyzer] Features for '{package_name}': {features}")
    
    prediction = model.predict(live_features_df)[0] # Get the 0 or 1 prediction
    probabilities = model.predict_proba(live_features_df)[0] # Get the [0.1, 0.9] confidence
    
    print(f"[AI Analyzer] Prediction: {prediction}, Prob: {probabilities}")

    return {
        "package_name": package_name,
        "features": features,
        "prediction": int(prediction), # 0 for Safe, 1 for Risky
        "confidence": {
            "safe": round(probabilities[0] * 100, 2),
            "risky": round(probabilities[1] * 100, 2)
        }
    }