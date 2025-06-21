import json
import dash
import dash_bootstrap_components as dbc
from dash import dcc, html, Input, Output, callback
import pandas as pd
import plotly.express as px
import flask
import socketio
import tldextract
import sys
import psycopg2
from psycopg2.extras import RealDictCursor
import threading
import queue
from pathlib import Path
import time
from functools import lru_cache
import inotify_simple
import logging
from datetime import datetime, timedelta
import os

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Server Setup
server = flask.Flask(__name__)
sio = socketio.Server(async_mode="threading")
app = dash.Dash(
    __name__,
    external_stylesheets=[dbc.themes.DARKLY],
    server=server,
    suppress_callback_exceptions=True,
    use_pages=False,  # Disable pages feature
    pages_folder=""  # Set empty pages folder
)
sio_app = socketio.WSGIApp(sio, server)

# Get user info from environment or command line
CURRENT_USER = sys.argv[1] if len(sys.argv) > 1 else "default_user"
CURRENT_USER_role = sys.argv[2] if len(sys.argv) > 2 else "user"

# Database configuration
DB_CONFIG = {
    "dbname": "WatchTower",
    "user": "postgres",
    "password": "12345",
    "host": "localhost",
    "port": "5432"
}

# Cache for log data
LOG_CACHE = {
    'data': None,
    'last_update': 0,
    'cache_duration': 5  # Cache duration in seconds
}

# Queue for real-time updates
update_queue = queue.Queue()

# --- Theme for Plots ---
def apply_black_theme(fig):
    fig.update_layout(
        plot_bgcolor="#121212",
        paper_bgcolor="#121212",
        font=dict(color="white", family="Segoe UI"),
        title_font=dict(color="#BB86FC", size=16, family="Segoe UI"),
        xaxis=dict(showgrid=True, gridcolor="#2C2C54", zerolinecolor="#2C2C54", tickfont=dict(color="white")),
        yaxis=dict(showgrid=True, gridcolor="#2C2C54", zerolinecolor="#2C2C54", tickfont=dict(color="white")),
        hoverlabel=dict(bgcolor="#333", font=dict(color="white"))
    )
    return fig

# --- Color Palette ---
theme_colors = ['#BB86FC', '#82AAFF', '#64FFDA', '#F48FB1', '#FFD54F']

# --- Navigation Links ---
if CURRENT_USER_role == "admin":
    nav_links = [
        dbc.NavLink(" Chat", href="/chat", active=True, style={"color": "#BB86FC"}),
        dbc.NavLink(" Tracking ", href="#alerts", style={"color": "#82AAFF"}),
        dbc.NavLink(" User Management ", href="#traffic", style={"color": "#BB86FC"}),
        dbc.NavLink(" Settings ", href="#dns", style={"color": "#82AAFF"}),
        dbc.NavLink(" Log OUT ", href="#settings", style={"color": "#BB86FC"}),
    ]
else:
    nav_links = [
        dbc.NavLink(" Chat", href="/chat", active=True, style={"color": "#BB86FC"}),
        dbc.NavLink(" Tracking ", href="#alerts", style={"color": "#82AAFF"}),
        dbc.NavLink(" Settings ", href="#dns", style={"color": "#82AAFF"}),
        dbc.NavLink(" Log OUT ", href="#settings", style={"color": "#BB86FC"}),
    ]

# --- Navbar ---
navbar = dbc.Navbar(
    dbc.Container([
        dbc.Row([
            dbc.Col(html.Div("Intrusion Detection System Analytics", style={
                "fontWeight": "bold",
                "fontSize": "32px",
                "color": "#0BA0E3",
                "fontFamily": "Segoe UI"
            })),
        ], align="center", className="g-0"),
    ]),
    color="#1A1A2E",
    dark=True,
    sticky="top",
    style={"boxShadow": "0 4px 12px rgba(11, 160, 227, 0.7)"}
)

# --- Cards ---
def create_card(title, value, color):
    return dbc.Card(
        dbc.CardBody([
            html.H6(title, className="card-title", style={"color": "white", "fontWeight": "600", "fontFamily": "Segoe UI"}),
            html.H3(value, style={"color": color, "fontWeight": "bold", "fontFamily": "Segoe UI"})
        ]),
        style={
            "backgroundColor": "#22223B",
            "borderRadius": "12px",
            "boxShadow": "0 8px 24px rgba(123, 31, 162, 0.3)",
            "border": "none",
            "height": "100%"
        },
        className="mb-4"
    )

# --- Layout ---
app.layout = dbc.Container([
    navbar,

    dbc.Row([
        dbc.Col(id="total-alerts-card", width=3),
        dbc.Col(id="total-traffic-card", width=3),
        dbc.Col(id="total-dns-card", width=3),
        dbc.Col(id="top-attack-card", width=3),
    ], className="mb-5", style={"marginTop": "2rem"}),

    dbc.Row([
        dbc.Col(dcc.Graph(id="alert-trend"), width=4),
        dbc.Col(dcc.Graph(id="event-bar"), width=4),
        dbc.Col(dcc.Graph(id="dns-traffic-bar"), width=4)
    ], className="mb-5"),

    dbc.Row([
        dbc.Col(dcc.Graph(id="protocol-distribution"), width=4),
        dbc.Col(dcc.Graph(id="top-source-ips"), width=4),
        dbc.Col(dcc.Graph(id="top-destination-ips"), width=4)
    ], className="mb-5"),

    dcc.Interval(id="interval-update", interval=30000, n_intervals=0)
],
fluid=True,
style={
    "backgroundColor": "#121212",
    "paddingLeft": "2rem",
    "paddingRight": "2rem",
    "paddingBottom": "3rem",
    "minHeight": "100vh"
})

@lru_cache(maxsize=100)
def read_eve_json(cache_key=None, batch_size=1000, max_logs=5000):
    """Read log file with caching and batch processing"""
    current_time = time.time()
    
    # Return cached data if still valid
    if LOG_CACHE['data'] is not None and current_time - LOG_CACHE['last_update'] < LOG_CACHE['cache_duration']:
        return LOG_CACHE['data']
    
    logs = []
    # Create timezone-aware three_days_ago instead of seven
    three_days_ago = datetime.now().astimezone().replace(microsecond=0) - timedelta(days=3)
    batch = []
    eve_path = "/var/log/suricata/eve.json"
    
    try:
        # Check if file exists and is readable
        if not Path(eve_path).exists():
            logger.error(f"Eve.json file not found at {eve_path}")
            # Try to create test data
            create_test_data()
            if not Path(eve_path).exists():
                return []
        
        if not os.access(eve_path, os.R_OK):
            logger.error(f"No read permission for {eve_path}")
            return []
            
        file_size = Path(eve_path).stat().st_size
        if file_size == 0:
            logger.warning("Eve.json file is empty")
            create_test_data()
            if Path(eve_path).stat().st_size == 0:
                return []
        
        logger.info(f"Attempting to read eve.json (size: {file_size/1024/1024:.2f} MB)...")
        
        # Read file from end to get most recent logs first
        with open(eve_path, "rb") as f:
            # Seek to end of file
            f.seek(0, 2)
            file_size = f.tell()
            
            # Initialize variables for reading backwards
            chunk_size = 8192  # Increased chunk size for better performance
            position = file_size
            line_count = 0
            incomplete_line = ""
            
            while position > 0 and len(logs) < max_logs:
                # Move back one chunk or to start of file
                chunk_size = min(chunk_size, position)
                position -= chunk_size
                f.seek(position)
                chunk = f.read(chunk_size).decode('utf-8')
                
                # Add any previous incomplete line
                if incomplete_line:
                    chunk += incomplete_line
                    incomplete_line = ""
                
                # Split into lines
                lines = chunk.split('\n')
                
                # If we're not at the start, first line is incomplete
                if position > 0:
                    incomplete_line = lines[0]
                    lines = lines[1:]
                
                # Process lines in reverse (most recent first)
                for line in reversed(lines):
                    if not line.strip():
                        continue
                    
                    try:
                        log_data = json.loads(line)
                        # Filter out stats events and check timestamp
                        if log_data.get("event_type") != "stats":
                            # Parse the timestamp
                            timestamp_str = log_data.get("timestamp", "")
                            try:
                                # Parse timestamp with timezone info
                                log_timestamp = pd.to_datetime(timestamp_str).to_pydatetime()
                                # Ensure timestamp has timezone info
                                if log_timestamp.tzinfo is None:
                                    log_timestamp = log_timestamp.astimezone()
                                
                                if log_timestamp >= three_days_ago:
                                    batch.append(log_data)
                                    line_count += 1
                                    
                                    # Process batch when it reaches batch_size
                                    if len(batch) >= batch_size:
                                        logs.extend(batch)
                                        batch = []
                                        
                                    # Check if we've reached max_logs
                                    if line_count >= max_logs:
                                        break
                                else:
                                    # Since we're reading newest to oldest, if we hit an old log, we can stop
                                    position = 0
                                    break
                            except ValueError:
                                continue
                    except json.JSONDecodeError:
                        continue
                    except Exception as e:
                        logger.error(f"Unexpected error processing line: {str(e)}")
                        continue
            
            # Add remaining batch
            if batch:
                logs.extend(batch)
        
        if not logs:
            logger.warning("No valid log entries found in eve.json")
        else:
            logger.info(f"Successfully read {len(logs)} log entries from the last 3 days")
        
        # Update cache
        LOG_CACHE['data'] = logs
        LOG_CACHE['last_update'] = current_time
        return logs
        
    except FileNotFoundError:
        logger.error(f"Eve.json file not found at {eve_path}")
        create_test_data()
        return []
    except PermissionError:
        logger.error(f"Permission denied when accessing {eve_path}")
        return []
    except Exception as e:
        logger.error(f"Error reading eve.json: {str(e)}")
        return []

def create_test_data():
    """Create test data if eve.json doesn't exist or is empty"""
    eve_path = Path("/var/log/suricata/eve.json")
    
    try:
        # Create directory if it doesn't exist
        eve_path.parent.mkdir(parents=True, exist_ok=True)
        
        logger.info("Creating test data...")
        test_alerts = [
            {
                "event_type": "alert",
                "alert": {
                    "signature": "Test Alert - Potential SQL Injection",
                    "severity": "high"
                },
                "src_ip": "192.168.1.100",
                "dest_ip": "10.0.0.1",
                "proto": "TCP",
                "timestamp": datetime.now().astimezone().isoformat()
            },
            {
                "event_type": "alert",
                "alert": {
                    "signature": "Test Alert - Port Scan Detected",
                    "severity": "medium"
                },
                "src_ip": "192.168.1.101",
                "dest_ip": "10.0.0.2",
                "proto": "TCP",
                "timestamp": datetime.now().astimezone().isoformat()
            },
            {
                "event_type": "dns",
                "dns": {
                    "rrname": "example.com",
                    "rrtype": "A"
                },
                "src_ip": "192.168.1.102",
                "dest_ip": "8.8.8.8",
                "proto": "UDP",
                "timestamp": datetime.now().astimezone().isoformat()
            }
        ]
        
        # Try to create the file with proper permissions
        with open(eve_path, "w", encoding="utf-8") as f:
            for alert in test_alerts:
                f.write(json.dumps(alert) + "\n")
                
        logger.info("Test data created successfully")
        
    except PermissionError:
        logger.error("Permission denied when trying to create test data")
    except Exception as e:
        logger.error(f"Error creating test data: {str(e)}")

def monitor_logs():
    """Monitor log file for changes using inotify"""
    eve_path = "/var/log/suricata/eve.json"
    
    try:
        # Create test data if file doesn't exist
        if not Path(eve_path).exists():
            logger.info("Eve.json not found, creating test data...")
            create_test_data()
        
        inotify = inotify_simple.INotify()
        watch_flags = inotify_simple.flags.MODIFY | inotify_simple.flags.CREATE
        
        try:
            watch_descriptor = inotify.add_watch(eve_path, watch_flags)
        except (FileNotFoundError, PermissionError) as e:
            logger.error(f"Could not set up file monitoring: {str(e)}")
            logger.info("Falling back to polling...")
            while True:
                time.sleep(1)
                update_queue.put(True)
                
        logger.info(f"Successfully set up file monitoring for {eve_path}")
        while True:
            try:
                for event in inotify.read(timeout=1000):
                    if event.wd == watch_descriptor:
                        # Check if file still exists and is readable
                        if Path(eve_path).exists() and os.access(eve_path, os.R_OK):
                            # Invalidate cache to force reload
                            LOG_CACHE['last_update'] = 0
                            # Signal update to dashboard
                            update_queue.put(True)
                        else:
                            logger.warning(f"File {eve_path} no longer accessible, creating test data...")
                            create_test_data()
                time.sleep(0.1)  # Small delay to prevent CPU overuse
            except Exception as e:
                logger.error(f"Error during file monitoring: {str(e)}")
                time.sleep(1)  # Wait before retrying
                
    except Exception as e:
        logger.error(f"Error setting up file monitoring: {str(e)}")
        logger.info("Falling back to polling...")
        while True:
            time.sleep(1)
            update_queue.put(True)

# Start log monitoring in background
monitor_thread = threading.Thread(target=monitor_logs, daemon=True)
monitor_thread.start()

@lru_cache(maxsize=1)
def json_to_dataframe(cache_key=None):
    """Convert logs to DataFrame with caching"""
    logs = read_eve_json()
    if not logs:
        return pd.DataFrame()
    
    # Optimize DataFrame creation
    df = pd.json_normalize(logs)
    
    # Handle event_type column first
    if 'event_type' in df.columns:
        # Fill NA values before converting to category
        df['event_type'] = df['event_type'].fillna("Unknown")
        df['event_type'] = df['event_type'].astype('category')
    
    # Handle timestamp column
    if 'timestamp' in df.columns:
        # Convert timestamps with timezone handling
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        # Convert all timestamps to naive timestamps for display
        if not df.empty:
            df['timestamp'] = df['timestamp'].dt.tz_convert(None)
    
    return df

@app.callback(
    [
        Output("total-alerts-card", "children"),
        Output("total-traffic-card", "children"),
        Output("total-dns-card", "children"),
        Output("top-attack-card", "children"),
        Output("alert-trend", "figure"),
        Output("event-bar", "figure"),
        Output("dns-traffic-bar", "figure"),
        Output("protocol-distribution", "figure"),
        Output("top-source-ips", "figure"),
        Output("top-destination-ips", "figure")
    ],
    Input("interval-update", "n_intervals")
)
def update_dashboard(n):
    # Force cache refresh if there's an update
    try:
        update_queue.get_nowait()
        # Invalidate caches
        read_eve_json.cache_clear()
        json_to_dataframe.cache_clear()
    except queue.Empty:
        pass
    
    df = json_to_dataframe(cache_key=n)  # Use n as cache key
    if df.empty:
        empty_fig = px.bar(title="No Data Available")
        empty_fig = apply_black_theme(empty_fig)
        no_data = create_card("No Data", "-", "#BBB")
        return no_data, no_data, no_data, no_data, empty_fig, empty_fig, empty_fig, empty_fig, empty_fig, empty_fig

    # Calculate metrics efficiently using value_counts once
    event_type_counts = df["event_type"].value_counts()
    total_alerts = int(event_type_counts.get("alert", 0))
    total_dns = int(event_type_counts.get("dns", 0))
    total_traffic = int(df.shape[0])
    top_attack = event_type_counts.index[0] if not event_type_counts.empty else "N/A"

    # Create cards
    alerts_card = create_card("Total Alerts", total_alerts, "#BB86FC")
    traffic_card = create_card("Total Traffic Logs", total_traffic, "#82AAFF")
    dns_card = create_card("Total DNS Queries", total_dns, "#BB86FC")
    attack_card = create_card("Top Attack Type", top_attack, "#82AAFF")

    # Create figures efficiently
    alert_df = df[df["event_type"] == "alert"].copy()
    # Sort by timestamp for proper trend display
    if not alert_df.empty:
        alert_df = alert_df.sort_values("timestamp")
    
    line_fig = px.line(alert_df, x="timestamp", y="event_type", title="Intrusion Alerts Over Time", markers=True)
    line_fig.update_traces(line_color='#BB86FC', marker=dict(color='#82AAFF'))
    line_fig = apply_black_theme(line_fig)

    # Reuse event_type_counts for bar chart
    event_type_df = event_type_counts.reset_index()
    event_type_df.columns = ["Event Type", "Count"]
    event_bar_fig = px.bar(
        event_type_df,
        x="Count",
        y="Event Type",
        title="Event Type Distribution",
        orientation="h",
        color="Event Type",
        text_auto=True,
        color_discrete_sequence=theme_colors,
        category_orders={"Event Type": event_type_df["Event Type"].tolist()}
    )
    event_bar_fig = apply_black_theme(event_bar_fig)

    # Process DNS data efficiently
    dns_raw = df.get("dns.rrname", pd.Series())
    if not dns_raw.empty:
        simplified_domains = dns_raw.apply(lambda x: tldextract.extract(x).domain if isinstance(x, str) else "Unknown")
        dns_counts = simplified_domains.value_counts().reset_index()
        dns_counts.columns = ["Domain", "Count"]
        dns_counts = dns_counts.sort_values(by="Count", ascending=False)
        dns_fig = px.bar(
            dns_counts.head(10),
            x="Domain",
            y="Count",
            title="Top 10 DNS Queries",
            color="Domain",
            text_auto=True,
            color_discrete_sequence=theme_colors
        )
        dns_fig.update_layout(xaxis_tickangle=-45, bargap=0.3)
        dns_fig = apply_black_theme(dns_fig)
    else:
        dns_fig = px.bar(title="No DNS Data")
        dns_fig = apply_black_theme(dns_fig)

    # Create remaining charts efficiently
    proto_counts = df.get("proto", pd.Series()).value_counts()
    proto_fig = px.pie(
        values=proto_counts.values,
        names=proto_counts.index,
        title="Protocol Distribution",
        hole=0.6,
        color_discrete_sequence=theme_colors
    )
    proto_fig = apply_black_theme(proto_fig)

    # Get top IPs efficiently
    src_ip_counts = df.get("src_ip", pd.Series()).value_counts().reset_index()
    src_ip_counts.columns = ["Source IP", "Count"]
    src_fig = px.pie(
        src_ip_counts.head(5),
        names="Source IP",
        values="Count",
        title="Top 5 Source IPs",
        hole=0.6,
        color_discrete_sequence=theme_colors
    )
    src_fig = apply_black_theme(src_fig)

    dst_ip_counts = df.get("dest_ip", pd.Series()).value_counts().reset_index()
    dst_ip_counts.columns = ["Destination IP", "Count"]
    dst_fig = px.bar(
        dst_ip_counts.head(5),
        x="Destination IP",
        y="Count",
        title="Top 5 Destination IPs",
        color="Destination IP",
        text_auto=True,
        color_discrete_sequence=theme_colors
    )
    dst_fig.update_traces(textfont=dict(color="Black", size=18))
    dst_fig = apply_black_theme(dst_fig)

    return alerts_card, traffic_card, dns_card, attack_card, line_fig, event_bar_fig, dns_fig, proto_fig, src_fig, dst_fig

# --- Main ---
if __name__ == "__main__":
    app.run(debug=False, port=8050)

