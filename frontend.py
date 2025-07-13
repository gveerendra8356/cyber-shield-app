import streamlit as st
import requests
import pandas as pd

# --- Page Configuration ---
st.set_page_config(
    page_title="CyberShield Dashboard",
    page_icon="🛡️",
    layout="wide"
)

# --- Backend API URLs ---
SCAN_URL = " https://cyber-shield-sf2e.onrender.com/scan-email"
LOGS_URL = "https://cyber-shield-sf2e.onrender.com/get-logs"
RISK_URL = " https://cyber-shield-sf2e.onrender.com/calculate-risk"
THREAT_LOGS_URL = " https://cyber-shield-sf2e.onrender.com/get-threat-logs"
LOGIN_URL = " https://cyber-shield-sf2e.onrender.com/login"

# ==============================================================================
#                      HELPER FUNCTIONS (DEFINED ONCE)
# ==============================================================================

def display_threat_logs():
    """Fetches and displays threat logs from the desktop agent."""
    try:
        response = requests.get(THREAT_LOGS_URL)
        if response.status_code == 200:
            logs = response.json()
            if logs:
                df = pd.DataFrame(logs)
                df = df[['timestamp', 'threat_type', 'details']]
                df.rename(columns={'timestamp': 'Timestamp', 'threat_type': 'Threat Type', 'details': 'Details'}, inplace=True)
                st.dataframe(df, use_container_width=True)
            else:
                st.info("No threats detected yet. The agent is monitoring for new file and folder creations.")
        else:
            st.error("Could not fetch threat logs from the server.")
    except requests.exceptions.ConnectionError:
        st.error("Connection Error: Could not connect to the backend.")

def display_email_logs():
    """Fetches and displays logs of detected spam emails."""
    try:
        logs_response = requests.get(LOGS_URL)
        if logs_response.status_code == 200:
            logs = logs_response.json()
            if logs:
                df = pd.DataFrame(logs)
                df = df[['timestamp', 'prediction', 'scanned_text']]
                df.rename(columns={'timestamp': 'Timestamp', 'prediction': 'Prediction', 'scanned_text': 'Scanned Content'}, inplace=True)
                st.dataframe(df, use_container_width=True)
            else:
                st.info("No spam emails have been detected or logged yet.")
        else:
            st.error("Could not fetch email scan logs from the server.")
    except requests.exceptions.ConnectionError:
        st.error("Connection Error: Could not connect to the backend to fetch logs.")

def display_risk_results_page(results):
    """Displays the calculated risk score and recommendations."""
    score = results.get("score", 0)
    risk_level = results.get("risk_level", "Unknown")
    recommendations = results.get("recommendations", [])
    total_score = results.get('total_possible_score', 100)
    st.subheader("Your Results")
    if risk_level == "Low": st.success(f"Your Cyber Hygiene Score is: **{score}/{total_score}** (Risk Level: Low)")
    elif risk_level == "Medium": st.warning(f"Your Cyber Hygiene Score is: **{score}/{total_score}** (Risk Level: Medium)")
    else: st.error(f"Your Cyber Hygiene Score is: **{score}/{total_score}** (Risk Level: High)")
    if recommendations:
        st.write("Personalized recommendations to improve your security:")
        for rec in recommendations: st.markdown(f"- {rec}")
    if st.button("Assess Again"):
        st.session_state.risk_results = None
        st.rerun()

def display_risk_form_page():
    """Displays the questionnaire form for the risk audit."""
    with st.form("risk_assessment_form"):
        questions = {
            "q1": "Do you use Multi-Factor Authentication (MFA) on all critical accounts (email, banking)?",
            "q2": "Do all employees use strong, unique passwords for different services?",
            "q3": "Do you have a policy against using public Wi-Fi for work purposes?",
            "q4": "Do you regularly back up all important business data?",
            "q5": "Have your employees received training on how to spot phishing emails in the last year?"
        }
        answers = {q_id: st.radio(q_text, ("Yes", "No"), key=q_id, horizontal=True) for q_id, q_text in questions.items()}
        if st.form_submit_button("Calculate My Score"):
            try:
                response = requests.post(RISK_URL, json={"answers": answers})
                if response.status_code == 200:
                    st.session_state.risk_results = response.json()
                    st.rerun()
                else: st.error("Could not calculate score. Server returned an error.")
            except requests.exceptions.ConnectionError:
                st.error("Connection Error: Could not connect to the backend.")

# ==============================================================================
#                           MAIN PAGE LAYOUT
# ==============================================================================

st.title("🛡️ CyberShield Threat Detection & Awareness Platform")
st.write("The complete security suite for your small business.")

tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "🤖 Automated Gmail Scanner",
    "🖥️ Desktop Threat Monitor",
    "📧 Manual Phishing Scanner",
    "📊 Scan & Threat Logs",
    "🎓 Awareness & Audit"
])

# --- Tab 1: Automated Gmail Scanner ---
with tab1:
    st.header("Automated Real-time Gmail Protection")
    st.write("Connect your Gmail account once to get continuous, automated scanning of all incoming emails.")
    st.divider()
    st.subheader("Connection Status")
    st.info("The backend service is now running in the background, checking for new emails automatically every minute.")
    st.success("You have already authorized your account. No further action is needed!")
    st.write("Detected spam emails will automatically appear in the 'Scan & Threat Logs' tab.")
    st.divider()
    st.subheader("Re-authorize or Change Account")
    st.write("If you need to connect a different Gmail account or re-authorize the application, use the button below.")
    st.link_button("Connect or Re-authorize Gmail", url=LOGIN_URL)

# --- Tab 2: Desktop Threat Monitor ---
with tab2:
    st.header("Live Desktop Threat Monitor")
    st.info("This dashboard shows real-time alerts from the CyberShield Desktop Agent.")
    if st.button("🔄 Refresh Threat Alerts"):
        pass
    display_threat_logs()

# --- Tab 3: Manual Phishing Scanner ---
with tab3:
    st.header("Manual Phishing Scanner")
    email_text = st.text_area("Paste email content here to scan:", height=200, key="email_scanner_input")
    if st.button("Scan Email Manually"):
        if email_text:
            payload = {"text": email_text}
            try:
                response = requests.post(SCAN_URL, json=payload)
                if response.status_code == 200:
                    result = response.json()
                    prediction = result.get("prediction")
                    if prediction == "spam":
                        st.error("This looks like a Phishing Email!")
                    else:
                        st.success("This seems to be a Safe Email.")
                    st.info("This manual scan has also been logged. Check the 'Scan & Threat Logs' tab.")
                else:
                    st.error(f"Error: {response.status_code}")
            except requests.exceptions.ConnectionError:
                st.error("Connection Error.")
        else:
            st.warning("Please enter text to scan.")

# --- Tab 4: Scan & Threat Logs ---
with tab4:
    st.header("Email Scan Logs")
    st.write("This log shows the history of all spam emails detected by both the manual and automated scanners.")
    if st.button("🔄 Refresh Email Logs"):
        pass
    display_email_logs()

# --- Tab 5: Awareness & Audit ---
with tab5:
    st.header("Cyber Hygiene Audit & Training")
    with st.expander("Calculate Your Cyber Risk Score", expanded=True):
        if 'risk_results' not in st.session_state:
            st.session_state.risk_results = None
        if st.session_state.risk_results:
            display_risk_results_page(st.session_state.risk_results)
        else:
            display_risk_form_page()
    st.divider()
    with st.expander("View Employee Awareness Training"):
        st.subheader("Recognizing Phishing Emails")
        st.image("https://storage.googleapis.com/gweb-uniblog-publish-prod/images/phishing-attack-social-engineering-s.max-1100x1100.jpg", use_container_width=True)
        st.markdown("**Key things to look for:**\n- Urgent or Threatening Language.\n- Generic Greetings.\n- Suspicious Links or Attachments.\n- Poor Grammar and Spelling.\n- Unusual Sender Address.")
        st.subheader("Creating Strong Passwords")
        st.markdown("**Best Practices:**\n- Length is Strength (12+ characters).\n- Use a Mix of character types.\n- Unique for Every Account.\n- Use a Password Manager.")