import json
import time
import re
import os
import signal
import sys
from pathlib import Path
from typing import ClassVar, Dict, Any, Optional, Generator
import ipaddress
import requests
import httpx
from phi.agent import Agent
from phi.tools.shell import ShellTools
from phi.tools.website import WebsiteTools
from phi.tools.googlesearch import GoogleSearch
from phi.tools.hackernews import HackerNews
from phi.tools.file import FileTools
from phi.tools import tool
from phi.model.google import Gemini
from phi.model.groq import Groq
from phi.model.huggingface import HuggingFaceChat
from functools import wraps  # Add this import


# Rate limiting decorator
def rate_limit_decorator(max_calls=10, period=60):
    calls = []
    
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            now = time.time()
            # Remove old calls
            while calls and calls[0] < now - period:
                calls.pop(0)
            
            if len(calls) >= max_calls:
                wait_time = calls[0] + period - now
                print(f"⏳ Rate limit reached. Waiting {wait_time:.2f} seconds...")
                time.sleep(wait_time)
            
            calls.append(time.time())
            return func(*args, **kwargs)
        return wrapper
    return decorator



# Load API keys from environment variables or use defaults for development
# In production, remove defaults and require proper environment variables
os.environ["HF_TOKEN"] = os.environ.get("HF_TOKEN", "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")
os.environ["GROQ_API_KEY"] = os.environ.get("GROQ_API_KEY", "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")
os.environ["GOOGLE_API_KEY"] = os.environ.get("GOOGLE_API_KEY", "AIzaSyAqensT_hePKgWtSD3suCwcF6Ob7brgQHg")
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "2f3af6e09775fcbceb97b594f57be80dd59fb89eeff4425e6bf95562ea3cd08f574cbba7c12b710c")

# Configure models
model_huggingface = HuggingFaceChat(
    id="mistralai/Mistral-7B-Instruct-v0.1",
    max_tokens=4096,
)

model_llama = Groq(id="llama-3.3-70b-versatile")
mini_model = Gemini(id="gemini-1.5-flash")

# Basic agents
shell_agent = Agent(
    name="Shell Operator",
    role="Executes system commands through the shell.",
    tools=[ShellTools()],
    model=mini_model
)

website_agent = Agent(
    name="Website Browser",
    role="Browses and interacts with websites.",
    tools=[WebsiteTools()],
    model=mini_model
)

search_agent = Agent(
    name="Google Searcher",
    role="Searches the web using Google.",
    tools=[GoogleSearch()],
    model=mini_model
)

hackernews_agent = Agent(
    name="HackerNews Reader",
    role="Fetches top stories from Hacker News.",
    tools=[HackerNews()],
    model=mini_model
)

file_agent = Agent(
    name="File Manager",
    role="Reads and writes files locally.",
    tools=[FileTools()],
    model=mini_model
)


def is_valid_ip(ip: str) -> bool:
    """Validate if a string is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

import subprocess

@tool(name="send_desktop_notification", description="Sends a notification to the desktop environment")
def send_desktop_notification(title: str, message: str) -> str:
    """
    Send a desktop notification using notify-send.
    
    Args:
        title (str): Title of the notification.
        message (str): Body of the notification.
        
    Returns:
        str: Result message indicating success or failure.
    """

    # Validate inputs
    if not isinstance(title, str) or not title.strip():
        return "❌ Error: Invalid or empty title."
    if not isinstance(message, str) or not message.strip():
        return "❌ Error: Invalid or empty message."

    # Preview message (only first 100 chars, if longer)
    preview = message[:100] + ("..." if len(message) > 100 else "")
    print(f"🖥️ Sending Desktop Notification: Title='{title}', Message='{preview}'")

    try:
        # Sanitize input strings (basic replacements)
        safe_title = title.replace('"', "'").replace("`", "'")
        safe_message = message.replace('"', "'").replace("`", "'")

        # Build the command
        command = ["notify-send", "--", safe_title, safe_message]
        print(f"🔧 Executing command: {' '.join(command)}")

        # Execute the command
        result = subprocess.run(command, capture_output=True, text=True, check=False)

        if result.returncode == 0:
            print("✅ Notification sent successfully.")
            return "Notification sent successfully."
        else:
            error_msg = (
                f"❌ Failed to send notification. Return code: {result.returncode}. "
                f"Error: {result.stderr.strip()}"
            )
            if "DBus" in result.stderr or "DISPLAY" in result.stderr:
                error_msg += (
                    " (Hint: A display server and active D-Bus session are required. "
                    "This may not work in headless or server environments.)"
                )
            print(error_msg)
            return error_msg

    except FileNotFoundError:
        error_msg = "❌ Error: 'notify-send' command not found. Try installing it with: sudo apt install libnotify-bin"
        print(error_msg)
        return error_msg

    except Exception as e:
        error_msg = f"❌ Unexpected error: {str(e)}"
        print(error_msg)
        return error_msg


@tool(name="block_ip", description="Blocks a malicious IP address using iptables")
def block_ip(ip: str) -> str:
    """Block an IP address using iptables with proper validation."""
    # Input validation
    if not ip or not isinstance(ip, str):
        return "Error: Invalid IP address format"
    
    # Verify this is a valid IP address to prevent command injection
    if not is_valid_ip(ip):
        return f"Error: '{ip}' is not a valid IP address"
    
    try:
        # Use a list of arguments instead of string formatting for better security
        # This prevents command injection by not using shell=True
        import subprocess
        result = subprocess.run(
            ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True,
            text=True,
            check=True
        )
        
        # Log the successful IP block
        with open("blocked_ips.log", "a") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - Blocked IP: {ip}\n")
            
        return f"Successfully blocked IP: {ip}"
    
    except subprocess.CalledProcessError as e:
        error_msg = f"Failed to block IP {ip}: {e.stderr}"
        print(f"❌ {error_msg}")
        return error_msg
    
    except subprocess.SubprocessError as e:
        error_msg = f"Subprocess error while blocking IP {ip}: {str(e)}"
        print(f"❌ {error_msg}")
        return error_msg
        
    except Exception as e:
        error_msg = f"Unexpected error while blocking IP {ip}: {str(e)}"
        print(f"❌ {error_msg}")
        return error_msg


@tool(name="log_event", description="Logs an event to a local file for storage or analysis")
def log_event(log_data: str) -> str:
    """Log event data to a file with error handling."""
    if not log_data or not isinstance(log_data, str):
        return "Error: Invalid log data format"
        
    try:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        formatted_log = f"[{timestamp}] {log_data}"
        
        # Ensure directory exists
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        
        log_file = log_dir / "classified_logs.txt"
        with open(log_file, "a", encoding='utf-8') as f:
            f.write(formatted_log + "\n")
        return f"Log written to {log_file}"
        
    except IOError as e:
        error_msg = f"I/O error writing to log file: {str(e)}"
        print(f"❌ {error_msg}")
        return error_msg
        
    except Exception as e:
        error_msg = f"Error writing to log file: {str(e)}"
        print(f"❌ {error_msg}")
        return error_msg


@tool(name="check_ip", description="Checks the reputation of an IP address using AbuseIPDB")
def check_ip(ip: str) -> Dict[str, Any]:
    """Check IP reputation with AbuseIPDB with validation and error handling."""
    # Input validation
    if not ip or not isinstance(ip, str):
        return {"error": "Invalid IP address format"}
    
    # Verify this is a valid IP address
    if not is_valid_ip(ip):
        return {"error": f"'{ip}' is not a valid IP address"}
    
    try:
        response = requests.get(
            f"https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={
                "Key": ABUSEIPDB_API_KEY,
                "Accept": "application/json"
            },
            timeout=10  # Set timeout to prevent hanging
        )
        
        if response.status_code == 200:
            return response.json()
        else:
            return {
                "error": f"API returned status code {response.status_code}",
                "message": response.text
            }
            
    except requests.exceptions.Timeout:
        return {"error": "Request to AbuseIPDB timed out"}
        
    except requests.exceptions.ConnectionError:
        return {"error": "Connection error while contacting AbuseIPDB"}
        
    except Exception as e:
        return {"error": f"Error checking IP reputation: {str(e)}"}


alert_agent = Agent(
    name="Alert Sender",
    role="Sends alerts via desktop notifications when needed",
    tools=[send_desktop_notification],
    model=mini_model
)

blocker_agent = Agent(
    name="IP Blocker",
    role="Blocks malicious IPs using iptables",
    tools=[block_ip],
    model=mini_model
)

logger_agent = Agent(
    name="Event Logger",
    role="Logs events to local file",
    tools=[log_event],
    model=mini_model
)

ip_checker_agent = Agent(
    name="IP Reputation Checker",
    role="Checks if IPs are malicious using reputation service",
    tools=[check_ip],
    model=mini_model
)

cybersecurity_team = Agent(
    name="Suricata Security",
    model=mini_model,
    team=[
        shell_agent,
        website_agent,
        search_agent,
        hackernews_agent,
        file_agent,
        alert_agent,
        blocker_agent,
        logger_agent,
        ip_checker_agent
    ],
    instructions=[
        "You are a cybersecurity AI agent responsible for monitoring and analyzing logs generated by Suricata IDS in real time.",
        "Your task is to process incoming logs that are in JSON format and take the following steps for each log entry:",
        "1. Understand the Log: Parse the log and identify the type of event. Only proceed if the event type is 'alert'.",
        "2. Analyze the Alert:",
        "   - Read the signature and severity of the alert.",
        "   - Determine the threat level based on the 'severity' field. Severity levels range from 1 (high risk) to 5 (low risk).",
        "   - Extract useful information like `src_ip`, `dest_ip`, `signature`, `protocol`, and `timestamp`.",
        "3. Classify the Threat:",
        "   - Classify the log as one of the following: `High Risk`, `Moderate Risk`, or `Low Risk`.",
        "   - Base the classification on the severity level and the nature of the signature.",
        "   - Provide a short explanation for your classification.",
        "4. Take Action:",
        "   - If High Risk: Block the source IP using the `block_ip` tool and send an alert using the `send_alert` tool.",
        "   - If Moderate Risk: Send an alert using the `send_alert` tool, and recommend manual review.",
        "   - If Low Risk: Log the event using the `log_event` tool, no immediate action needed.",
        "5. Respond Clearly:",
        "   - Always return a structured response in plain English including:",
        "     - Threat classification.",
        "     - Action taken.",
        "     - Summary of the reason behind the action.",
        "Avoid acting on events that are not alerts (like DNS or HTTP logs). If a log is malformed or missing important fields, you can skip it and respond with 'Invalid log format.'",
        "Always prioritize clarity, security, and correct actions."
    ],
    show_tool_calls=True,
    markdown=True,
)

# Apply the decorator to your cybersecurity_team.run method
original_run = cybersecurity_team.run
cybersecurity_team.run = rate_limit_decorator(max_calls=10, period=60)(original_run)

def process_alert(log):
    """Process an alert with fallback to different models if rate limited"""
    # Skip non-alert events
    if log.get("event_type") != "alert":
        return "Skipped: Not an alert event"

    models = [mini_model, model_llama, model_huggingface]
    current_model_index = 0
    
    while current_model_index < len(models):
        try:
            # Set the current model
            cybersecurity_team.model = models[current_model_index]
            
            # Format the input to be more explicit
            input_msg = {
                "event_type": log.get("event_type"),
                "signature": log.get("alert", {}).get("signature"),
                "severity": log.get("alert", {}).get("severity"),
                "src_ip": log.get("src_ip"),
                "dest_ip": log.get("dest_ip"),
                "protocol": log.get("proto"),
                "timestamp": log.get("timestamp")
            }
            
            # Format instructions for more consistent responses
            instructions = """
            Analyze this security alert and respond with one of these actions:
            1. "BLOCK: [reason]" - If the activity is clearly malicious
            2. "ALERT: [reason]" - If the activity is suspicious but needs investigation
            3. "MONITOR: [reason]" - If the activity should just be watched
            
            Keep the response concise and focus on the action and reason.
            """
            
            # Try processing with the current model
            response = cybersecurity_team.run(
                input=f"{instructions}\nAlert details:\n{json.dumps(input_msg, indent=2)}"
            )
            
            # Convert response to string if needed
            if response is None:
                return "MONITOR: No response from agent"
                
            # Extract the actual response text
            response_text = str(response).strip()
            
            # Log the response for debugging
            print(f"🤖 AI Response: {response_text}")
            
            return response_text
                
        except Exception as e:
            if "429" in str(e) and current_model_index < len(models) - 1:
                # Rate limited, try the next model
                current_model_index += 1
                print(f"⚠️ Rate limited. Switching to alternate model {current_model_index}...")
            else:
                # Other error or no more models to try
                print(f"❌ Error processing alert: {str(e)}")
                return f"MONITOR: Error analyzing alert: {str(e)}"


def follow_logs_improved(file_path: str, poll_interval: float = 0.1) -> Generator[Dict[str, Any], None, None]:
    """
    More efficient log monitoring using inotify when available, with fallback to polling.
    
    Args:
        file_path: Path to the log file to monitor
        poll_interval: How often to check for new data when polling (seconds)
        
    Yields:
        Parsed JSON log entries
    """
    log_file_path = Path(file_path)
    
    if not log_file_path.exists():
        print(f"⚠️ Warning: Log file {file_path} does not exist. Creating an empty file.")
        log_file_path.touch()
    
    # Try to use inotify for efficient monitoring (Linux only)
    try:
        # Import only if needed
        import inotify_simple
        
        print(f"📂 Starting to monitor log file using inotify: {file_path}")
        
        # Initialize inotify
        inotify = inotify_simple.INotify()
        watch_flags = inotify_simple.flags.MODIFY
        watch_descriptor = inotify.add_watch(str(log_file_path), watch_flags)
        
        # Open the file and seek to the end
        with open(log_file_path, "r", encoding='utf-8', errors='replace') as f:
            f.seek(0, 2)  # Move to end of file
            
            while True:
                # Wait for events
                for event in inotify.read(timeout=1000):  # 1 second timeout
                    if event.wd == watch_descriptor:
                        # File was modified, check for new lines
                        while True:
                            line = f.readline()
                            if not line:
                                break  # No more new lines
                                
                            try:
                                log_data = json.loads(line)
                                yield log_data
                            except json.JSONDecodeError as e:
                                print(f"⚠️ Error decoding JSON log entry: {e}")
                                print(f"Problem line: {line[:100]}...")  # Print first 100 chars
                                continue
                
    except (ImportError, NameError):
        # Fallback to polling if inotify is not available (non-Linux systems)
        print(f"📂 Starting to monitor log file using polling: {file_path}")
        
        # Use polling approach
        with open(log_file_path, "r", encoding='utf-8', errors='replace') as f:
            f.seek(0, 0)  # Move to end of file
            
            while True:
                line = f.readline()
                if not line:
                    time.sleep(poll_interval)  # Wait before checking again
                    continue
                    
                try:
                    log_data = json.loads(line)
                    yield log_data
                except json.JSONDecodeError as e:
                    print(f"⚠️ Error decoding JSON log entry: {e}")
                    print(f"Problem line: {line[:100]}...")  # Print first 100 chars
                    continue


# Setup graceful shutdown
def signal_handler(sig, frame):
    print("\n📣 Shutting down gracefully...")
    # Any cleanup code here (close files, etc.)
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

def main():
    """Main application entry point with error handling."""
    # Set up log directory
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    
    print("🔒 Starting Suricata Security AI Agent")
    print("Press Ctrl+C to exit")
    
    try:
        # Using the improved log monitoring function
        for log in follow_logs_improved("eve.json"):
            if not isinstance(log, dict):
                print(f"⚠️ Invalid log format, expected dict but got {type(log)}")
                continue
                
            if log.get("event_type")!= "stats":
                print(f"\n📥 New Alert Log: {log}")
                
                try:
                    # Use the new process_alert function with model fallback
                    response = process_alert(log)
                    print(f"🤖 Agent Response: {response}")
                    
                    # Print the full response
                    print(f"🔍 Full Response: {response}")
                    
                    if "Alert sent" in str(response):
                        print("✅ Alert was sent to Telegram successfully.")
                    else:
                        print("⚠️ There was an issue with sending the alert.")
                        
                except Exception as e:
                    print(f"❌ Error processing alert: {e}")
                    # Use the function correctly with error handling
                    try:
                        log_event(f"Error processing alert: {str(e)}")
                    except Exception as log_error:
                        print(f"❌ Failed to log error: {log_error}")
                    continue
                    
    except KeyboardInterrupt:
        print("\n👋 Exiting by user request")
        
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        # Log the error before exiting with better error handling
        try:
            log_event(f"Fatal error: {str(e)}")
        except Exception as log_error:
            print(f"❌ Failed to log fatal error: {log_error}")
        return 1
        
    return 0


if __name__ == "__main__":
    sys.exit(main())