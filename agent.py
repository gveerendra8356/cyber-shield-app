import time
import os
import requests
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# --- Configuration ---
BACKEND_ALERT_URL = "http://127.0.0.1:8000/log-threat"
# Cooldown period in seconds to prevent duplicate alerts for the same path.
DEBOUNCE_SECONDS = 2.0

# --- Event Handler Class ---
class ThreatDetectionEventHandler(FileSystemEventHandler):
    def __init__(self):
        # This dictionary will store the last time we sent an alert for a specific path.
        # Key: file/folder path, Value: timestamp
        self.recent_events = {}

    def on_created(self, event):
        """This method is called only when a file or directory is CREATED."""
        
        current_time = time.time()
        path = event.src_path

        # --- DEBOUNCE LOGIC ---
        # Check if we have seen an event for this path recently.
        last_event_time = self.recent_events.get(path)
        
        if last_event_time and (current_time - last_event_time) < DEBOUNCE_SECONDS:
            # If it's too soon, ignore this event and do nothing.
            # print(f"[DEBUG] Ignoring duplicate event for: {path}")
            return
        
        # If we are here, it's a new, valid event.
        # Record the time of this new event.
        self.recent_events[path] = current_time
        
        # Determine the threat type and details.
        if event.is_directory:
            threat_type = "Folder Detected"
            details = f"A new folder was created: {path}"
        else:
            threat_type = "File Detected"
            details = f"A new file was created: {path}"
        
        print(f"[ALERT] {details}")
        self.send_alert_to_server(threat_type, details)

    def send_alert_to_server(self, threat_type, details):
        """Sends a notification to the main backend server."""
        try:
            payload = {"threat_type": threat_type, "details": details}
            requests.post(BACKEND_ALERT_URL, json=payload, timeout=5) # Added a timeout
            print(f"[*] Alert for '{details}' was sent to the server.")
        except requests.exceptions.ConnectionError:
            print(f"[!] Alert for '{details}' could not be sent. Is the backend server running?")
        except Exception as e:
            print(f"[ERROR] An unexpected error occurred while sending alert: {e}")

# --- Main Program Execution ---
if __name__ == "__main__":
    print("--- CyberShield Desktop Agent (v2 - with Debounce) ---")
    path_to_watch = os.path.join(os.path.expanduser('~'), 'OneDrive', 'Desktop')
    
    if not os.path.exists(path_to_watch):
        print(f"[FATAL ERROR] The directory to watch does not exist: {path_to_watch}")
        exit()

    print(f"[*] Monitoring directory: {path_to_watch}")
    print("[*] Create a new file or folder on your Desktop to test.")
    print("[*] Press Ctrl+C to stop the agent.")

    event_handler = ThreatDetectionEventHandler()
    observer = Observer()
    observer.schedule(event_handler, path_to_watch, recursive=True)
    observer.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Stopping agent...")
        observer.stop()
    
    observer.join()
    print("[*] Agent has been stopped.")