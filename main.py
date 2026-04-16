import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import re
import os
import json
from datetime import datetime

# --- 1. FEATURE EXTRACTION SCRIPT ---
def extract_features(url, email_body, sender_name, sender_email):
    features = {}
    features['url_length'] = len(url) if url else 0
    features['num_dots'] = url.count('.') if url else 0
    features['has_at_symbol'] = 1 if url and '@' in url else 0
    features['has_hyphen'] = 1 if url and '-' in url else 0
    features['has_ip_in_url'] = 1 if url and re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url) else 0
    
    clean_url = url.replace('http://', '').replace('https://', '') if url else ""
    features['url_depth'] = clean_url.count('/')
    features['has_double_slash'] = 1 if clean_url and '//' in clean_url else 0
    
    keywords = ['urgent', 'login', 'verify', 'bank', 'password', 'suspend', 'account', 'prize', 'winner']
    features['urgent_keywords'] = 0
    if email_body:
        body_lower = email_body.lower()
        if any(keyword in body_lower for keyword in keywords):
            features['urgent_keywords'] = 1
            
    features['mismatched_domain'] = 0
    if sender_name and sender_email:
        name_lower = sender_name.lower()
        email_lower = sender_email.lower()
        if 'google' in name_lower and 'google.com' not in email_lower:
            features['mismatched_domain'] = 1
        elif 'support' in name_lower and 'support' not in email_lower:
            features['mismatched_domain'] = 1
            
    return features


# --- 2. EXPLANATION LOGIC ---
def explain_result(features):
    reasons = []
    if features.get('url_length', 0) > 75:
        reasons.append("Exceptionally long URL.")
    if features.get('num_dots', 0) > 3:
        reasons.append("Too many subdomains detected (.dots).")
    if features.get('has_at_symbol', 0) == 1:
        reasons.append("Contains '@' symbol (Redirect trick).")
    if features.get('has_hyphen', 0) == 1:
        reasons.append("Hyphenated domain mimicking legitimate brands.")
    if features.get('has_ip_in_url', 0) == 1:
        reasons.append("Contains an IP address instead of a domain name.")
    if features.get('url_depth', 0) > 4:
        reasons.append("Deep subdirectories hiding the true payload.")
    if features.get('has_double_slash', 0) == 1:
        reasons.append("Contains suspicious double-slashes for redirection.")
    if features.get('urgent_keywords', 0) == 1:
        reasons.append("Manipulative/Urgent vocabulary in email.")
    if features.get('mismatched_domain', 0) == 1:
        reasons.append("Sender Display Name does not match Email Domain.")
        
    if not reasons:
        return "No red flags detected based on heuristics."
    return "Flagged because: " + ", ".join(reasons)


# --- 3. MODEL TRAINING ---
def train_model():
    dataset_path = os.path.join(os.path.dirname(__file__), 'phishing_dataset.csv')
    try:
        df = pd.read_csv(dataset_path)
    except FileNotFoundError:
        print("CRITICAL: phishing_dataset.csv not found! Using fallback dummy data.")
        df = pd.DataFrame([{
            'url_length': 25, 'num_dots': 2, 'has_at_symbol': 0, 'has_hyphen': 0, 
            'has_ip_in_url': 0, 'url_depth': 1, 'has_double_slash': 0, 
            'urgent_keywords': 0, 'mismatched_domain': 0, 'label': 0
        }])
        
    X = df.drop('label', axis=1)
    y = df['label']
    
    model = RandomForestClassifier(n_estimators=50, random_state=42)
    model.fit(X, y)
    return model


# --- 4. DATA PERSISTENCE (HYBRID DB LAYER) ---
import sqlite3
import pymongo

# Cloud Database Configuration (Insert your Atlas URI here)
MONGO_URI = "mongodb+srv://<username>:<password>@cluster0.your-mongodb.net/?retryWrites=true&w=majority"
USE_CLOUD_DB = False if "<username>" in MONGO_URI else True

DB_FILE = os.path.join(os.path.dirname(__file__), 'deepshield.db')

def init_db():
    if USE_CLOUD_DB: return # MongoDB manages schema natively
    
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            target TEXT,
            prediction TEXT,
            confidence TEXT,
            reason TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_db()

def save_log(url, prediction_num, safe_conf, mal_conf, reason):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    target = url if url else "Email Content Only"
    prediction = "Malicious" if prediction_num == 1 else "Safe"
    confidence = f"{mal_conf:.1f}%" if prediction_num == 1 else f"{safe_conf:.1f}%"
    
    if USE_CLOUD_DB:
        try:
            client = pymongo.MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
            db = client.deepshield
            db.scans.insert_one({
                "timestamp": timestamp,
                "target": target,
                "prediction": prediction,
                "confidence": confidence,
                "reason": reason
            })
            return
        except Exception as e:
            print(f"Cloud DB Error: {e}. Falling back to local SQLite.")

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('INSERT INTO scans (timestamp, target, prediction, confidence, reason) VALUES (?, ?, ?, ?, ?)',
              (timestamp, target, prediction, confidence, reason))
    conn.commit()
    conn.close()

def fetch_all_logs(limit=50):
    if USE_CLOUD_DB:
        try:
            client = pymongo.MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
            db = client.deepshield
            docs = list(db.scans.find({}, {"_id":0}).sort("timestamp", -1).limit(limit))
            return docs
        except Exception:
            pass

    if os.path.exists(DB_FILE):
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute('SELECT * FROM scans ORDER BY id DESC LIMIT ?', (limit,))
        rows = [dict(r) for r in c.fetchall()]
        conn.close()
        return rows
    return []

# --- 5. FASTAPI APPLICATION SETUP ---
app = FastAPI(title="DeepShield Analytics API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

model = train_model()

class AnalyzeRequest(BaseModel):
    url: Optional[str] = ""
    email_body: Optional[str] = ""
    sender_name: Optional[str] = ""
    sender_email: Optional[str] = ""

@app.post("/api/analyze")
def analyze_threat(request: AnalyzeRequest):
    features = extract_features(request.url, request.email_body, request.sender_name, request.sender_email)
    input_df = pd.DataFrame([features])
    
    prediction = int(model.predict(input_df)[0])
    scores = model.predict_proba(input_df)[0]
    
    safe_conf = float(scores[0] * 100)
    mal_conf = float(scores[1] * 100)
    explanation = explain_result(features)
    
    save_log(request.url, prediction, safe_conf, mal_conf, explanation)
    
    return {
        "prediction": prediction,
        "safe_confidence": safe_conf,
        "malicious_confidence": mal_conf,
        "explanation": explanation,
        "features": features
    }

@app.get("/api/logs")
def get_logs():
    return fetch_all_logs()

@app.get("/api/stats")
def get_stats():
    logs = fetch_all_logs(99999)
    safe = sum(1 for log in logs if log.get('prediction') == 'Safe')
    mal = sum(1 for log in logs if log.get('prediction') != 'Safe')
    return {"safe_count": safe, "malicious_count": mal, "total": len(logs)}
