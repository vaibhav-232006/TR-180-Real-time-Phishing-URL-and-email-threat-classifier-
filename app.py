import streamlit as st
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

# --- 1. FEATURE EXTRACTION SCRIPT ---
def extract_features(url, email_body, sender_name, sender_email):
    """
    Extracts numerical and boolean features from the provided URL and email text.
    These features represent common indicators of phishing attempts.
    """
    features = {}
    
    # --- URL Features ---
    # Phishing URLs are often very long to hide the actual domain
    features['url_length'] = len(url) if url else 0
    
    # Excessive dots are common in sub-domain manipulation (e.g., login.yourbank.com.malicious.com)
    features['num_dots'] = url.count('.') if url else 0
    
    # The '@' symbol is used to ignore everything before it in a URL, directing users elsewhere
    features['has_at_symbol'] = 1 if url and '@' in url else 0
    
    # Hyphens are rarely used in legitimate primary domains but often in fake ones (e.g., paypal-secure.com)
    features['has_hyphen'] = 1 if url and '-' in url else 0
    
    # --- Email Body Features ---
    # Phishers create a sense of urgency to make users act without thinking
    keywords = ['urgent', 'login', 'verify', 'bank', 'password', 'suspend', 'account']
    features['urgent_keywords'] = 0
    if email_body:
        body_lower = email_body.lower()
        # If any of the suspicious keywords are in the email body, flag it (1)
        if any(keyword in body_lower for keyword in keywords):
            features['urgent_keywords'] = 1
            
    # --- Domain Mismatch Check ---
    # Checking if the sender says they are "Google" but the email is "support@xyz.com"
    features['mismatched_domain'] = 0
    if sender_name and sender_email:
        name_lower = sender_name.lower()
        email_lower = sender_email.lower()
        
        # Simple beginner heuristic:
        # If a well-known name is in the sender name but not in the email domain
        if 'google' in name_lower and 'google.com' not in email_lower:
            features['mismatched_domain'] = 1
        elif 'bank' in name_lower and 'bank' not in email_lower:
            features['mismatched_domain'] = 1
            
    return features


# --- 2. MACHINE LEARNING MODEL ---
# We use st.cache_resource so Streamlit only trains the model once and reuses it, 
# ensuring processing time is extremely fast (under 1 second).
@st.cache_resource
def train_dummy_model():
    """
    Trains a simple Scikit-Learn Random Forest Classifier on a small dummy dataset.
    You can easily replace the dummy data with a real CSV dataset later.
    """
    # Dummy data: 10 samples (5 Safe, 5 Malicious)
    data = {
        'url_length':       [25, 150, 30, 200, 40,  180, 20,  160, 22,  190],
        'num_dots':         [2,  5,   2,  6,   1,   4,   2,   5,   1,   7  ],
        'has_at_symbol':    [0,  1,   0,  1,   0,   1,   0,   1,   0,   1  ],
        'has_hyphen':       [0,  1,   1,  1,   0,   1,   0,   1,   0,   1  ],
        'urgent_keywords':  [0,  1,   0,  1,   0,   1,   0,   1,   0,   1  ],
        'mismatched_domain':[0,  1,   0,  1,   0,   1,   0,   1,   0,   1  ],
        'label':            [0,  1,   0,  1,   0,   1,   0,   1,   0,   1  ] # 0 = Safe, 1 = Malicious
    }
    
    # Load into a Pandas DataFrame
    df = pd.DataFrame(data)
    
    # Split features (X) and labels (y)
    X = df.drop('label', axis=1)
    y = df['label']
    
    # Initialize Random Forest (simple model with 10 trees to be fast)
    model = RandomForestClassifier(n_estimators=10, random_state=42)
    
    # 'Train' the model
    model.fit(X, y)
    
    return model


# --- 3. THE 'WHY' LOGIC ---
def explain_result(features):
    """
    Translates the numerical features back into plain English 
    so users can understand exactly why a threat was flagged.
    """
    reasons = []
    
    if features.get('url_length', 0) > 75:
        reasons.append("The URL is exceptionally long, which is a common tactic to hide fake domains.")
    if features.get('num_dots', 0) > 3:
        reasons.append("The URL has too many dots, suggesting possible sub-domain manipulation.")
    if features.get('has_at_symbol', 0) == 1:
        reasons.append("The URL contains an '@' symbol, which can redirect browsers to a hidden destination.")
    if features.get('has_hyphen', 0) == 1:
        reasons.append("Hyphens are present in the URL, a trick used to visually mimic legitimate brands (like paypal-secure.com).")
    if features.get('urgent_keywords', 0) == 1:
        reasons.append("The email uses manipulative keywords like 'urgent', 'login', or 'verify' to rush your decision.")
    if features.get('mismatched_domain', 0) == 1:
        reasons.append("The sender's name claims to be from a reputable source, but the actual email domain does not match.")
        
    if not reasons:
        return "No obvious red flags were detected based on simple heuristics."
        
    # Join the explanations into a readable sentence
    return "Flagged because: " + " ".join(reasons)


# --- 4. WEB DASHBOARD (STREAMLIT) ---
def main():
    # Set up the visual configuration of our web app
    st.set_page_config(page_title="Phishing Threat Classifier", page_icon="🛡️")
    
    # App Title and Description
    st.title("🛡️ Real-Time Phishing Threat Classifier")
    st.markdown("Instantly analyze URLs and Emails to detect potential phishing threats using Machine Learning heuristics.")
    
    # Load our machine learning model
    model = train_dummy_model()
    
    # --- UI Inputs ---
    st.subheader("Input Data")
    
    url_input = st.text_input("🔗 URL to Test", placeholder="https://example.com/login")
    
    # Put sender name and email side-by-side using Streamlit columns
    col1, col2 = st.columns(2)
    with col1:
        sender_name_input = st.text_input("👤 Sender Name (Optional)", placeholder="e.g. Google Support")
    with col2:
        sender_email_input = st.text_input("✉️ Sender Email (Optional)", placeholder="e.g. no-reply@scam-domain.com")
        
    email_body_input = st.text_area("📝 Email Body", placeholder="Paste the suspicious email text here...")
    
    # --- Action Button ---
    if st.button("🔍 Analyze for Threats", type="primary"):
        
        # Ensure at least a URL or Email body was provided before analyzing
        if not url_input and not email_body_input:
            st.warning("Please provide a URL or an Email Body to analyze.")
            return

        with st.spinner("Analyzing in real-time..."):
            # Step 1: Extract features from user inputs
            features = extract_features(url_input, email_body_input, sender_name_input, sender_email_input)
            
            # Streamlit needs the data in a DataFrame format to send to the model
            input_df = pd.DataFrame([features])
            
            # Step 2: Get predictions and confidence scores
            # predict() returns 0 or 1. predict_proba() returns the % confidence for both classes.
            prediction = model.predict(input_df)[0]
            confidence_scores = model.predict_proba(input_df)[0]
            
            safe_confidence = confidence_scores[0] * 100
            malicious_confidence = confidence_scores[1] * 100
            
            # Step 3: Get plain English explanation
            explanation = explain_result(features)
            
            st.divider() # Visual separator
            
            # --- Display Results ---
            st.subheader("📊 Analysis Results")
            
            if prediction == 1: # 1 means Malicious
                st.error(f"🚨 **MALICIOUS THREAT DETECTED** (Confidence: {malicious_confidence:.1f}%)")
                st.warning(f"**Why?** {explanation}")
            else: # 0 means Safe
                if malicious_confidence > 30: # Custom threshold for partial suspicion
                    st.warning(f"⚠️ **SUSPICIOUS** (Safe Confidence: {safe_confidence:.1f}%)")
                    st.info(f"**Notes:** {explanation}")
                else:
                    st.success(f"✅ **SAFE** (Confidence: {safe_confidence:.1f}%)")
                    st.info(f"**Notes:** {explanation}")
            
            # Optional: Allow the user to peek under the hood at the extracted numerical features
            with st.expander("🛠️ View Extracted Under-the-Hood Features (For Hackathon Judges)"):
                st.json(features)

# Required syntax to ensure Streamlit runs the main function
if __name__ == "__main__":
    main()
