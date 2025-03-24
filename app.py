from flask import Flask, request, jsonify
from flask_cors import CORS  # Import CORS
import joblib
import os
import pandas as pd
import re
import numpy as np

app = Flask(__name__)
CORS(app)  # Enable CORS for all requests

# ✅ Path to the model file
MODEL_PATH = "optimized_phishing_model_fixed.pkl"

# ✅ Ensure the model file exists
if not os.path.exists(MODEL_PATH):
    raise FileNotFoundError(f"❌ Model file '{MODEL_PATH}' not found! Make sure it is in your repository.")

# ✅ Load the trained model
try:
    model = joblib.load(MODEL_PATH)
    print("✅ Model loaded successfully!")
except Exception as e:
    print(f"❌ Error loading model: {e}")

# ✅ Feature extraction function (updated with all required features)
def extract_features(url):
    domain = re.sub(r"https?://", "", url).split("/")[0]
    path = url.split("/", 3)[-1] if "/" in url else ""

    # Feature extraction logic
    features = {
        "having_IP": 1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0,
        "have_At": 1 if "@" in url else 0,
        "url_depth": url.count('/'),
        "redirection": 1 if "//" in url[7:] else 0,
        "https_domain": 1 if url.startswith("https") else 0,
        "tiny_URL": 1 if len(domain) < 10 else 0,
        "prefix_suffix": 1 if "-" in domain else 0,
        "url_length": len(url),
        "hostname_length": len(domain),
        "num_digits": sum(c.isdigit() for c in url),
        "num_special_chars": sum(not c.isalnum() for c in url),
        "num_subdomains": domain.count("."),
        "https": 1 if url.startswith("https") else 0,
        "num_params": url.count("?"),
        "path_length": len(path),
        "num_fragments": url.count("#"),
        "domain_length": len(domain),
        "domain_hyphens": domain.count("-"),
        "domain_numbers": sum(c.isdigit() for c in domain),
        "tld_length": len(domain.split(".")[-1]) if "." in domain else 0,
        "subdomain_length": len(domain.split(".")[0]) if "." in domain else 0,
        "is_numeric_domain": 1 if domain.isdigit() else 0,
        "digit_letter_ratio": sum(c.isdigit() for c in domain) / max(sum(c.isalpha() for c in domain), 1),
        "domain_entropy": -sum((domain.count(c)/len(domain)) * np.log2(domain.count(c)/len(domain)) for c in set(domain)),
        "num_popups": 0,  # Placeholder (requires JavaScript analysis)
        "num_redirects": 0,  # Placeholder (requires behavior analysis)
        "num_forms": 0,  # Placeholder (requires page analysis)
        "eval_usage": 1 if "eval(" in url else 0,
        "escape_usage": 1 if "%20" in url or "%3C" in url else 0,
        "settimeout_usage": 0,  # Placeholder (requires script analysis)
        "iframe_redirection": 0,  # Placeholder (requires HTML parsing)
        "status_bar_customization": 0,  # Placeholder (requires HTML parsing)
        "disable_right_click": 0,  # Placeholder (requires JavaScript analysis)
        "website_forwarding": 0  # Placeholder (requires behavior analysis)
    }

    return features

@app.route('/')
def home():
    return "Phishing Detection API is Running!"

@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.get_json()
        url = data.get("url", "")

        if not url:
            return jsonify({"error": "URL is required"}), 400

        # Extract features
        features = extract_features(url)
        feature_df = pd.DataFrame([features])

        # ✅ Debugging: Print model expected features and extracted features
        print("Model expects these features:", model.feature_names_in_)
        print("Extracted features:", list(features.keys()))

        # Ensure feature names match model training data
        model_features = model.feature_names_in_
        missing_features = set(model_features) - set(feature_df.columns)
        extra_features = set(feature_df.columns) - set(model_features)

        if missing_features:
            return jsonify({"error": f"Missing features: {list(missing_features)}"}), 500
        if extra_features:
            return jsonify({"error": f"Unexpected extra features: {list(extra_features)}"}), 500

        # Make prediction
        prediction = model.predict(feature_df)[0]
        result = "Phishing" if prediction == 1 else "Legitimate"

        return jsonify({"url": url, "prediction": result})

    except Exception as e:
        print(f"Error during prediction: {e}")
        return jsonify({"error": "Internal Server Error", "message": str(e)}), 500

# ✅ Fix: Ensure Flask uses port 10000
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))  # Force Flask to use port 10000
    app.run(host="0.0.0.0", port=port, debug=True)
