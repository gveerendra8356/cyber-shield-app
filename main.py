import os
import datetime
import base64
import joblib
import sqlite3
from typing import Dict, List
from fastapi import FastAPI, Request as FastAPIRequest
from fastapi.responses import RedirectResponse
from pydantic import BaseModel

# --- Google API Imports ---
from google.auth.transport.requests import Request as GoogleRequest
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# --- Background Scheduler Import ---
from apscheduler.schedulers.background import BackgroundScheduler

# --- Configuration ---
DB_NAME = 'cybershield_log.db'
TOKEN_FILE = 'token.json'
CREDENTIALS_FILE = 'credentials.json'
# We add '.modify' scope to be able to mark emails as read after scanning
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly', 'https://www.googleapis.com/auth/gmail.modify']

# --- Global Variables ---
app = FastAPI()
model = None
creds = None
# Initialize the scheduler to run in the background
scheduler = BackgroundScheduler(daemon=True)

# --- Pydantic Models (Data Structures) ---
class ScanRequest(BaseModel):
    text: str
class LogEntry(BaseModel):
    id: int; timestamp: str; scanned_text: str; prediction: str
class RiskRequest(BaseModel):
    answers: Dict[str, str]
class ThreatAlert(BaseModel):
    threat_type: str; details: str
class ThreatLogEntry(BaseModel):
    id: int; timestamp: str; threat_type: str; details: str

# --- Core Functions ---

def init_db():
    """Initializes the database and creates tables if they don't exist."""
    conn = sqlite3.connect(DB_NAME, check_same_thread=False) # `check_same_thread=False` is needed for APScheduler
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            scanned_text TEXT NOT NULL,
            prediction TEXT NOT NULL
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS threat_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            threat_type TEXT NOT NULL,
            details TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

def check_and_scan_emails():
    """The function that will be run automatically by the scheduler to scan emails."""
    global creds, model
    print(f"[{datetime.datetime.now()}] SCHEDULER: Running job: Checking for new emails...")

    if not creds or not creds.valid:
        # If credentials exist but are expired, refresh them
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(GoogleRequest())
            print("[SCHEDULER] Google credentials refreshed.")
        else:
            print("[SCHEDULER] Cannot check emails: User is not authenticated.")
            return

    try:
        service = build('gmail', 'v1', credentials=creds)
        # Find all unread messages
        results = service.users().messages().list(userId='me', q='is:unread').execute()
        messages = results.get('messages', [])

        if not messages:
            print("[SCHEDULER] No new unread messages found.")
            return

        print(f"[SCHEDULER] Found {len(messages)} new messages. Processing...")
        conn = sqlite3.connect(DB_NAME, check_same_thread=False)
        cursor = conn.cursor()

        for message_info in messages:
            msg_id = message_info['id']
            msg = service.users().messages().get(userId='me', id=msg_id, format='full').execute()
            
            payload = msg.get('payload', {})
            parts = payload.get('parts', [])
            email_body = ""

            if parts:
                for part in parts:
                    if part.get('mimeType') == 'text/plain':
                        data = part.get('body', {}).get('data')
                        if data:
                            email_body = base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
                            break
            
            if not email_body:
                email_body = msg.get('snippet', '')

            if email_body:
                prediction = model.predict([email_body])[0]
                print(f"[SCHEDULER] Scanned email (ID: {msg_id}). Prediction: {prediction}")

                if prediction == 'spam':
                    timestamp = datetime.datetime.now().isoformat()
                    # Log only spam emails to avoid clutter
                    cursor.execute("INSERT INTO scan_logs (timestamp, scanned_text, prediction) VALUES (?, ?, ?)",
                                   (timestamp, email_body[:1000], "spam (auto-detected)"))
                    conn.commit()
                    print(f"[SCHEDULER] Logged spam email (ID: {msg_id}) to database.")

                # Mark the email as read so it's not scanned again
                service.users().messages().modify(userId='me', id=msg_id, body={'removeLabelIds': ['UNREAD']}).execute()
        
        conn.close()

    except HttpError as error:
        print(f'[SCHEDULER] An API error occurred: {error}')
    except Exception as e:
        print(f'[SCHEDULER] An unexpected error occurred: {e}')


# --- FastAPI Startup and Shutdown Events ---

@app.on_event("startup")
def on_startup():
    """Actions to perform when the application starts up."""
    global model, creds, scheduler
    init_db()
    print("Database is ready.")
    
    print("Loading AI model...")
    model = joblib.load('phishing_model.pkl')
    print("Model loaded successfully.")
    
    print("Checking for existing Google credentials...")
    if os.path.exists(TOKEN_FILE):
        creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)
        print("Credentials loaded from token file.")
    
    # Start the scheduler and add the email scanning job
    scheduler.add_job(check_and_scan_emails, 'interval', seconds=60, id='email_scanner_job')
    scheduler.start()
    print("Background email scanner started. Will run every 60 seconds.")

@app.on_event("shutdown")
def on_shutdown():
    """Action to perform when the application shuts down."""
    print("Shutting down scheduler...")
    scheduler.shutdown()

# ==============================================================================
#                               API ENDPOINTS
# ==============================================================================

@app.get("/login", tags=["Google Auth"])
def login():
    flow = Flow.from_client_secrets_file(CREDENTIALS_FILE, scopes=SCOPES, redirect_uri='http://cyber-sheils-sf2e.onrender.com/callback')
    authorization_url, _ = flow.authorization_url(access_type='offline', include_granted_scopes='true')
    return RedirectResponse(authorization_url)

@app.get("/callback", tags=["Google Auth"])
def callback(request: FastAPIRequest):
    global creds
    code = request.query_params.get('code')
    flow = Flow.from_client_secrets_file(CREDENTIALS_FILE, scopes=SCOPES, redirect_uri='http://cyber-shield-sf2e.onrender.com/callback')
    flow.fetch_token(code=code)
    creds = flow.credentials
    with open(TOKEN_FILE, 'w') as token:
        token.write(creds.to_json())
    print("Tokens fetched and saved to token.json successfully.")
    return RedirectResponse(" http://cyber-shield-sf2e.onrender.com/?status=auth_success")

@app.post("/log-threat", tags=["Threat Agent"])
def log_threat(alert: ThreatAlert):
    conn = sqlite3.connect(DB_NAME, check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO threat_logs (timestamp, threat_type, details) VALUES (?, ?, ?)",
                   (datetime.datetime.now().isoformat(), alert.threat_type, alert.details))
    conn.commit()
    conn.close()
    return {"status": "success"}

@app.get("/get-threat-logs", response_model=List[ThreatLogEntry], tags=["Threat Agent"])
def get_threat_logs():
    conn = sqlite3.connect(DB_NAME, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM threat_logs ORDER BY timestamp DESC")
    logs = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return logs

@app.post("/scan-email", tags=["Email Scanner"])
def scan_email(request: ScanRequest):
    prediction = model.predict([request.text])[0]
    conn = sqlite3.connect(DB_NAME, check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO scan_logs (timestamp, scanned_text, prediction) VALUES (?, ?, ?)",
                   (datetime.datetime.now().isoformat(), request.text, prediction))
    conn.commit()
    conn.close()
    return {"text": request.text, "prediction": prediction}

@app.get("/get-logs", response_model=List[LogEntry], tags=["Email Scanner"])
def get_logs():
    conn = sqlite3.connect(DB_NAME, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scan_logs ORDER BY timestamp DESC")
    logs = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return logs

@app.post("/calculate-risk", tags=["Risk Assessment"])
def calculate_risk(request: RiskRequest):
    RISK_QUESTIONS = {
        "q1": {"weight": 30, "recommendation": "Enable MFA..."},
        "q2": {"weight": 20, "recommendation": "Enforce a strong password policy..."},
        "q3": {"weight": 10, "recommendation": "Create a policy to avoid public Wi-Fi..."},
        "q4": {"weight": 25, "recommendation": "Implement regular, automated backups..."},
        "q5": {"weight": 15, "recommendation": "Conduct regular security awareness training..."}
    }
    score = sum(RISK_QUESTIONS[q_id]['weight'] for q_id, answer in request.answers.items() if answer == "Yes")
    recommendations = [RISK_QUESTIONS[q_id]['recommendation'] for q_id, answer in request.answers.items() if answer == "No"]
    TOTAL_POSSIBLE_SCORE = sum(q['weight'] for q in RISK_QUESTIONS.values())
    if score >= 80: risk_level = "Low"
    elif score >= 50: risk_level = "Medium"
    else: risk_level = "High"
    return {"score": score, "total_possible_score": TOTAL_POSSIBLE_SCORE, "risk_level": risk_level, "recommendations": recommendations}

@app.get("/", tags=["General"])
def read_root():
    return {"message": "Welcome to the CyberShield API v2 with Automated Scanning"}