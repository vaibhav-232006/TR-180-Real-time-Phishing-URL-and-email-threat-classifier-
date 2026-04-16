# 🛡️ DeepShield - AI-Powered Phishing Threat Classifier

A comprehensive, multi-interface phishing detection system that leverages Machine Learning to analyze URLs and email content for potential phishing threats. Built with a FastAPI backend, Streamlit web dashboard, desktop GUI, and modern web frontend.

## 🌟 Features

- **Multi-Interface Access**: Choose between web dashboard (Streamlit), desktop application (CustomTkinter), or modern web frontend
- **Machine Learning Detection**: Random Forest Classifier trained on phishing heuristics and network flow features
- **VirusTotal Integration**: Enhanced URL scanning using VirusTotal API for real-time threat intelligence
- **Email Alert System**: Automatic email notifications when phishing URLs are detected
- **Real-Time Analysis**: Instant threat evaluation with confidence scores
- **Explainable AI**: Plain English explanations for every detection
- **Persistent Logging**: Hybrid database support (SQLite local + MongoDB Atlas cloud)
- **Analytics Dashboard**: Visual charts and statistics of scan history
- **RESTful API**: Full API with auto-generated documentation
- **Model Training**: Retrain the ML model with your own dataset

## 🏗️ Project Structure

```
tensor26/
├── app.py                 # Streamlit web dashboard
├── gui_app.py             # Desktop GUI application (CustomTkinter)
├── requirements.txt       # Python dependencies
├── start.bat              # Windows launcher script
├── backend/
│   ├── main.py            # FastAPI backend server
│   ├── api_checker.py     # VirusTotal API integration & email alerts
│   ├── train_model.py     # Model training script
│   ├── phishing_dataset.csv       # Primary training dataset
│   ├── Backup_phishing_dataset.csv # Backup training dataset
│   ├── phishing_model.pkl # Trained ML model (auto-generated)
│   ├── label_encoder.pkl  # Label encoder for model (auto-generated)
│   ├── deepshield.db      # SQLite database (auto-generated)
│   ├── scan_logs.json     # JSON scan logs
│   └── .env               # Environment variables (API keys, email config)
└── frontend/
    ├── index.html         # Web frontend HTML
    ├── style.css          # Web frontend styling
    └── script.js          # Web frontend JavaScript
```

## 🚀 Quick Start

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

### Installation

1. **Clone or download the repository**

```bash
cd tensor26
```

2. **Install dependencies**

```bash
pip install -r requirements.txt
```

3. **Configure environment variables (Optional)**

Create a `.env` file in the `backend/` directory for VirusTotal API and email alerts:

```env
VT_API_KEY=your_virustotal_api_key
EMAIL_SENDER=your_email@gmail.com
EMAIL_PASSWORD=your_app_password
EMAIL_RECEIVER=alert_recipient@email.com
```

### Running the Application

#### Option 1: All-in-One Launcher (Windows)

Double-click `start.bat` or run:

```bash
start.bat
```

This will start:
- FastAPI Backend on `http://localhost:8000`
- Web Frontend on `http://localhost:3000`

#### Option 2: Individual Components

**Start the Backend Server:**
```bash
uvicorn backend.main:app --reload --port 8000
```

**Start the Streamlit Dashboard:**
```bash
streamlit run app.py
```

**Start the Desktop GUI:**
```bash
python gui_app.py
```

**Start the Web Frontend:**
```bash
python -m http.server 3000 --directory frontend
```

**Run VirusTotal URL Scanner (Standalone):**
```bash
python backend/api_checker.py
```

## 📖 Usage

### Web Dashboard (Streamlit)

1. Open your browser to the Streamlit URL (typically `http://localhost:8501`)
2. Enter a suspicious URL in the input field
3. (Optional) Add sender name, email, and email body content
4. Click **"Analyze for Threats"**
5. View results with confidence scores and explanations

### Desktop Application (GUI)

1. Run `python gui_app.py`
2. Use the **Dashboard** tab to analyze URLs/emails
3. View **Telemetry** for scan history
4. Check **Settings** for system diagnostics

### Web Frontend

1. Open `http://localhost:3000` in your browser
2. Navigate between Dashboard, Analytics, and Scan Logs
3. Submit URLs and email content for analysis
4. View real-time charts and statistics

### VirusTotal Integration

The `api_checker.py` module provides enhanced scanning:
- Submit URLs to VirusTotal for multi-engine analysis
- Receive email alerts when phishing is detected
- Get detailed malicious/harmless detection counts

```bash
python backend/api_checker.py
# Enter a URL to scan with VirusTotal
```

### API Documentation

Access the auto-generated API docs at `http://localhost:8000/docs`

**Key Endpoints:**
- `POST /api/analyze` - Analyze a URL/email for phishing
- `GET /api/logs` - Retrieve scan history
- `GET /api/stats` - Get aggregate statistics

## 🔍 Detection Features

The ML model analyzes the following heuristics:

| Feature | Description |
|---------|-------------|
| URL Length | Exceptionally long URLs may hide fake domains |
| Number of Dots | Excessive subdomains indicate manipulation |
| @ Symbol | Used to redirect browsers to hidden destinations |
| Hyphens | Common in fake domains mimicking brands |
| IP in URL | Legitimate sites rarely use IP addresses |
| URL Depth | Deep paths may hide malicious payloads |
| Double Slash | Suspicious double-slashes for redirection |
| Urgent Keywords | Manipulative language like "urgent", "verify" |
| Domain Mismatch | Sender name doesn't match email domain |

### Network Flow Features (for model training)

| Feature | Description |
|---------|-------------|
| Flow Duration | Duration of the network flow |
| Total Fwd Packets | Number of forward packets |
| Total Bwd Packets | Number of backward packets |
| Average Packet Size | Mean packet size |
| Fwd Packet Length Max | Maximum forward packet length |
| Bwd Packet Length Max | Maximum backward packet length |
| Packet Length Mean | Mean of all packet lengths |
| Packet Length Std | Standard deviation of packet lengths |

## 🗄️ Database Configuration

### Local SQLite (Default)
Scan logs are automatically stored in `backend/deepshield.db`.

### MongoDB Atlas (Cloud)
To enable cloud storage, update the `MONGO_URI` in `backend/main.py`:

```python
MONGO_URI = "mongodb+srv://username:password@cluster.mongodb.net/"
```

## 🧠 Model Training

Retrain the ML model with your own dataset:

1. Prepare a CSV dataset with the required columns (see `backend/phishing_dataset.csv` for format)
2. Place it in the `backend/` directory
3. Run the training script:

```bash
cd backend
python train_model.py
```

The trained model (`phishing_model.pkl`) and label encoder (`label_encoder.pkl`) will be saved automatically.

## 📦 Dependencies

| Package | Purpose |
|---------|---------|
| fastapi | REST API framework |
| uvicorn | ASGI server |
| streamlit | Web dashboard |
| customtkinter | Modern desktop GUI |
| scikit-learn | Machine learning |
| pandas | Data processing |
| numpy | Numerical operations |
| pydantic | Data validation |
| pymongo | MongoDB connectivity |
| joblib | Model serialization |
| python-dotenv | Environment variable management |
| requests | HTTP requests (VirusTotal API) |

## 🔧 Customization

### Training with Your Own Dataset

Replace `backend/phishing_dataset.csv` with your own dataset containing these columns:
- `url_length`, `num_dots`, `has_at_symbol`, `has_hyphen`
- `has_ip_in_url`, `url_depth`, `has_double_slash`
- `urgent_keywords`, `mismatched_domain`, `label` (0=Safe, 1=Malicious)

### Adjusting Threat Threshold

In `gui_app.py`, modify the threshold value:
```python
if mal_conf > 15:  # Change 15 to your desired threshold
```

### Adding New Detection Features

1. Add feature extraction logic in `backend/main.py`'s `extract_features()` function
2. Update the training dataset with the new feature column
3. Retrain the model using `backend/train_model.py`

## 🛡️ Security Note

This tool is designed for educational and demonstration purposes. While it uses real phishing detection heuristics and VirusTotal integration, it should not be the sole method of phishing protection. Always use comprehensive security solutions for production environments.

**Important**: Never commit your `.env` file containing API keys and passwords to version control.

## 📄 License

MIT License - Feel free to use and modify for your projects.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Submit a pull request

---

**Built with ❤️ using Python, FastAPI, Streamlit, and CustomTkinter**