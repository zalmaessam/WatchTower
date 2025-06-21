#!/usr/bin/env python3
import customtkinter as ctk
from PIL import Image, ImageTk
import sys
import os
import subprocess
import threading
import socketio
import psycopg2
from psycopg2.extras import RealDictCursor
from datetime import datetime, timedelta
import time
from tkinter import filedialog
import hashlib
from license_checker import check_license
import tkinter as tk
import tkinter.font as tkfont
from tkinter import ttk, messagebox
import json
import queue
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from MINI_AGENT_NEW import process_alert, cybersecurity_team, log_event, follow_logs_improved
import webbrowser
import webview

# Constants
SIDEBAR_COLOR = "#1b1b1b"

class WatchTowerApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        # Start server.py and dashboard.py in background threads
        def start_server():
            try:
                import sys
                import os
                # Add the current directory to Python path
                sys.path.append(os.path.dirname(os.path.abspath(__file__)))
                from server import app, socketio
                socketio.run(app, host='0.0.0.0', port=5000, debug=False)
            except Exception as e:
                print(f"Error starting server: {e}")
            
        def start_dashboard():
            try:
                from dashboard import app as dashboard_app
                dashboard_app.run(port=8051, debug=False)
            except Exception as e:
                print(f"Error starting dashboard: {e}")
            
        # Start server thread
        server_thread = threading.Thread(target=start_server, daemon=True)
        server_thread.start()
        
        # Start dashboard thread
        dashboard_thread = threading.Thread(target=start_dashboard, daemon=True)
        dashboard_thread.start()
        
        # Give servers a moment to start
        time.sleep(1)

        # Initialize AI agent monitoring
        def start_ai_monitoring():
            print("🔒 Starting Suricata Security AI Agent")
            try:
                # Create logs directory if it doesn't exist
                log_dir = Path("logs")
                log_dir.mkdir(exist_ok=True)

                # Create test data if needed
                eve_path = Path("/var/log/suricata/eve.json")
                if not eve_path.exists() or eve_path.stat().st_size == 0:
                    print("Creating test data...")
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
                            "timestamp": datetime.now().isoformat()
                        }
                    ]
                    eve_path.parent.mkdir(parents=True, exist_ok=True)
                    with open(eve_path, "w", encoding="utf-8") as f:
                        for alert in test_alerts:
                            f.write(json.dumps(alert) + "\n")

                # Start monitoring logs
                for log in follow_logs_improved(str(eve_path)):
                    if not isinstance(log, dict):
                        print(f"⚠️ Invalid log format, expected dict but got {type(log)}")
                        continue
                    
                    if log.get("event_type") != "stats":
                        try:
                            response = process_alert(log)
                            print(f"🤖 AI Response: {response}")
                        except Exception as e:
                            print(f"❌ Error processing alert: {e}")
                            try:
                                log_event(f"Error processing alert: {str(e)}")
                            except Exception as log_error:
                                print(f"❌ Failed to log error: {log_error}")
            except Exception as e:
                print(f"❌ Fatal error in AI monitoring: {e}")

        # Start AI monitoring thread
        self.ai_monitor_thread = threading.Thread(target=start_ai_monitoring, daemon=True)
        self.ai_monitor_thread.start()
        
        if not check_license():
            self.destroy()
            exit("Access Denied: License invalid or expired.")
        
        # Initialize state
        self.current_frame = None
        self.username = None
        self.user_role = None
        
        # Database configuration
        self.db_config = {
            "dbname": "WatchTower",
            "user": "postgres",
            "password": "12345",
            "host": "localhost",
            "port": "5432"
        }
        
        # Set appearance
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        # Setup window
        self.geometry("1920x1080")
        self.configure(fg_color="black")
        self.title("WatchTower")
        
        # Set window icon
        icon = Image.open("/home/zalma/Downloads/watchtower/app_icon.png")
        icon_photo = ImageTk.PhotoImage(icon)
        self.wm_iconphoto(True, icon_photo)
        
        # Create main container
        self.container = ctk.CTkFrame(self, fg_color="black")
        self.container.pack(fill="both", expand=True)
        
        # Initialize frames dictionary
        self.frames = {}
        
        # Start with splash screen
        self.show_splash()
    
    def load_app_icon(self):
        img = Image.open("/home/zalma/Downloads/watchtower/watchtower/icons/logo.png")
        self.photo = ImageTk.PhotoImage(img)
        self.iconphoto(False, self.photo)
    
    def show_splash(self):
        # Clear any existing frames
        if self.current_frame:
            self.current_frame.pack_forget()
        
        # Create splash frame
        splash = SplashFrame(self.container, self)
        splash.pack(fill="both", expand=True)
        self.current_frame = splash
    
    def show_login(self):
        if self.current_frame:
            self.current_frame.pack_forget()
        
        login = LoginFrame(self.container, self)
        login.pack(fill="both", expand=True)
        self.current_frame = login
    
    def show_main_app(self, username, user_role):
        self.username = username
        self.user_role = user_role
        self.title(f"WatchTower - {username}")
        
        if self.current_frame:
            self.current_frame.pack_forget()
        
        main = MainFrame(self.container, self)
        main.pack(fill="both", expand=True)
        self.current_frame = main

class SplashFrame(ctk.CTkFrame):
    def __init__(self, parent, controller):
        super().__init__(parent, fg_color="#000000")
        self.controller = controller
        
        # Create a frame to center the content
        center_frame = ctk.CTkFrame(self, fg_color="transparent")
        center_frame.place(relx=0.5, rely=0.5, anchor="center")
        
        # load and preprocess the logo: strip out any near-black so only the icon remains
        logo_path = os.path.join(os.path.dirname(__file__), "/home/zalma/Downloads/watchtower/watchtower/icons/sp.png")
        pil = Image.open(logo_path).convert("RGBA")
        datas = pil.getdata()
        new_data = []
        for r, g, b, a in datas:
            # treat near-black as background → transparent
            if r < 10 and g < 10 and b < 10:
                new_data.append((0, 0, 0, 0))
            else:
                new_data.append((r, g, b, a))
        pil.putdata(new_data)
        
        # CTkImage from our RGBA - keeping the logo small (120x120)
        img = ctk.CTkImage(dark_image=pil, size=(120, 120))
        ctk.CTkLabel(center_frame, image=img, text="", fg_color="transparent")\
            .pack(pady=(0, 20))  # Reduced padding since we're centering properly
        
        # progress bar - centered under the logo
        self.progress = ctk.CTkProgressBar(center_frame, width=300)
        self.progress.pack()
        self.progress.set(0)
        
        # start animating
        self._animate()
    
    def _animate(self):
        val = self.progress.get() + 0.01
        if val < 1.0:
            self.progress.set(val)
            self.after(30, self._animate)
        else:
            self.controller.show_login()

class LoginFrame(ctk.CTkFrame):
    def __init__(self, parent, controller):
        super().__init__(parent, fg_color="black")
        self.controller = controller
        
        # Database configuration
        self.db_config = {
            "dbname": "WatchTower",
            "user": "postgres",
            "password": "12345",
            "host": "localhost",
            "port": "5432"
        }
        
        # Load background image
        self.load_background_image()
        
        # Create login form
        self.create_login_form()
    
    def load_background_image(self):
        # Left image panel (Curved left side only)
        try:
            img = Image.open("/home/zalma/Downloads/watchtower/watchtower/icons/loginimage.png").resize((600, 600))
            self.bg_img = ImageTk.PhotoImage(img)
            left_frame = tk.Label(self, image=self.bg_img, bg="black")
            left_frame.place(relx=0, rely=0, relwidth=0.6, relheight=1)
        except Exception as e:
            print("Image error:", e)
        
        # Right login frame (Curved left side only)
        self.right_frame = ctk.CTkFrame(self, fg_color="#2a2a2a", corner_radius=40)
        self.right_frame.place(relx=0.6, rely=0, relwidth=0.4, relheight=1)
    
    def create_login_form(self):
        # Load icons
        user_icon = ctk.CTkImage(
            Image.open("/home/zalma/Downloads/watchtower/watchtower/icons/username.png").resize((20, 20))
        )
        pass_icon = ctk.CTkImage(
            Image.open("/home/zalma/Downloads/watchtower/watchtower/icons/lock.png").resize((20, 20))
        )
        eye_open = ctk.CTkImage(
            Image.open("/home/zalma/Downloads/watchtower/watchtower/icons/eye.png").resize((20, 20))
        )
        eye_closed = ctk.CTkImage(
            Image.open("/home/zalma/Downloads/watchtower/watchtower/icons/eye-crossed.png").resize((20, 20))
        )
        
        # Centered content frame
        content_frame = ctk.CTkFrame(master=self.right_frame, fg_color="transparent", corner_radius=0)
        content_frame.place(relx=0.5, rely=0.5, anchor="center")
        
        # Titles
        ctk.CTkLabel(
            master=content_frame,
            text="Login",
            font=("Century Gothic", 30, "bold"),
            text_color="white"
        ).pack(pady=(10, 5), anchor="w", padx=40)
        
        ctk.CTkLabel(
            master=content_frame,
            text="Welcome back to WatchTower!",
            font=("Century Gothic", 18),
            text_color="gray"
        ).pack(pady=(0, 30), anchor="w", padx=40)
        
        # Username field
        email_row = ctk.CTkFrame(master=content_frame, fg_color="transparent", corner_radius=0)
        email_row.pack(padx=40, pady=(0, 5), anchor="w")
        
        ctk.CTkLabel(master=email_row, image=user_icon, text="").pack(side="left")
        ctk.CTkLabel(
            master=email_row,
            text="Username",
            font=("Century Gothic", 14),
            text_color="white"
        ).pack(side="left", padx=(5, 0))
        
        self.username_entry = ctk.CTkEntry(
            master=content_frame,
            placeholder_text="Username...",
            fg_color="white",
            text_color="black",
            border_color="gray",
            border_width=2,
            width=320,
            height=40,
            font=("Century Gothic", 14),
            corner_radius=20
        )
        self.username_entry.pack(padx=40, pady=(0, 2), anchor="w")
        
        self.username_error = ctk.CTkLabel(
            master=content_frame,
            text="",
            text_color="red",
            font=("Century Gothic", 12)
        )
        self.username_error.pack(anchor="w", padx=40, pady=(0, 3))
        
        # Password field
        pass_row = ctk.CTkFrame(master=content_frame, fg_color="transparent", corner_radius=0)
        pass_row.pack(padx=40, pady=(0, 2), anchor="w")
        
        ctk.CTkLabel(master=pass_row, image=pass_icon, text="").pack(side="left")
        ctk.CTkLabel(
            master=pass_row,
            text="Password",
            font=("Century Gothic", 14),
            text_color="white"
        ).pack(side="left", padx=(5, 0))
        
        self.password_entry = ctk.CTkEntry(
            master=content_frame,
            placeholder_text="Password",
            show="*",
            fg_color="white",
            text_color="black",
            border_color="gray",
            border_width=2,
            width=320,
            height=40,
            font=("Century Gothic", 14),
            corner_radius=20
        )
        self.password_entry.pack(padx=40, pady=(0, 2), anchor="w")
        
        # Eye button for password visibility
        self.eye_button = ctk.CTkButton(
            master=self.password_entry,
            image=eye_closed,
            width=20,
            height=20,
            text="",
            command=lambda: self.toggle_password(eye_open, eye_closed),
            fg_color="transparent",
            hover=False,
            corner_radius=0
        )
        self.eye_button.place(relx=0.93, rely=0.5, anchor="center")
        
        self.password_error = ctk.CTkLabel(
            master=content_frame,
            text="",
            text_color="red",
            font=("Century Gothic", 12)
        )
        self.password_error.pack(anchor="w", padx=40, pady=(0, 5))
        
        # Login button
        ctk.CTkButton(
            master=content_frame,
            width=150,
            height=40,
            text="Login",
            font=("Century Gothic", 16),
            fg_color="#0F386B",
            hover_color="#074173",
            text_color="white",
            command=self.login,
            corner_radius=20
        ).pack(pady=(10, 20))
    
    def toggle_password(self, eye_open, eye_closed):
        if self.password_entry.cget("show") == "*":
            self.password_entry.configure(show="")
            self.eye_button.configure(image=eye_open)
        else:
            self.password_entry.configure(show="*")
            self.eye_button.configure(image=eye_closed)
    
    def hash_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()
    
    def login(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        
        # Reset error messages
        self.username_error.configure(text="")
        self.password_error.configure(text="")
        self.username_entry.configure(border_color="gray")
        self.password_entry.configure(border_color="gray")
        
        # Validate input
        if not username and not password:
            self.username_error.configure(text="Please enter your email")
            self.password_error.configure(text="Please enter your password")
            self.username_entry.configure(border_color="red")
            self.password_entry.configure(border_color="red")
            return
        if not username:
            self.username_error.configure(text="Please enter your email")
            self.username_entry.configure(border_color="red")
            return
        if not password:
            self.password_error.configure(text="Please enter your password")
            self.password_entry.configure(border_color="red")
            return
        
        try:
            # Connect to database
            conn = psycopg2.connect(**self.db_config)
            cursor = conn.cursor()
            
            # Check credentials
            cursor.execute(
                "SELECT password_hash, userrole FROM login WHERE username = %s",
                (username,)
            )
            result = cursor.fetchone()
            
            if result is None:
                self.username_error.configure(text="Username not found.")
                self.username_entry.configure(border_color="red")
                return
            
            stored_hash, userrole = result
            if self.hash_password(password) != stored_hash:
                self.password_error.configure(text="Incorrect password.")
                self.password_entry.configure(border_color="red")
                return
            
            # Login successful
            self.controller.show_main_app(username, userrole)
            
        except Exception as e:
            print(f"Database error: {e}")
        finally:
            if 'conn' in locals():
                conn.close()

class ChatFrame(ctk.CTkFrame):
    def __init__(self, parent, controller):
        super().__init__(parent, fg_color="#131313")
        self.controller = controller
        
        # Initialize variables
        self.pinned_active_idx = 0
        self.active_friend = None
        self.last_enter_time = 0
        self.pinned_messages = []  # Store pinned messages
        self.replying_to = None  # Store message being replied to
        self.conversations = {}  # Initialize conversations dictionary
        self.unread_messages = {}  # Initialize unread messages dictionary
        
        # Database setup
        self.db_config = {
            "dbname": "WatchTower",
            "user": "postgres",
            "password": "12345",
            "host": "localhost",
            "port": "5432"
        }
        
        try:
            self.conn = psycopg2.connect(**self.db_config)
            self.cursor = self.conn.cursor(cursor_factory=RealDictCursor)
            
            # Create pinned_messages table if it doesn't exist
            self.cursor.execute("""
                CREATE TABLE IF NOT EXISTS pinned_messages (
                    id SERIAL PRIMARY KEY,
                    message TEXT NOT NULL,
                    pinned_by VARCHAR(100) REFERENCES login(username),
                    pinned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    conversation_with VARCHAR(100) REFERENCES login(username)
                )
            """)
            self.conn.commit()
        except Exception as e:
            print(f"Error connecting to database: {e}")
            self.conn = None
            self.cursor = None
        
        if self.conn:
            # Create messages table if it doesn't exist
            self.create_messages_table()
            
            # Get user data
            self.user_data = self.fetch_friends()
            
            # Load message history
            self.load_message_history()
            
            # Load pinned messages
            self.load_pinned_messages()
        else:
            self.user_data = {}
            
        # Socket.IO setup
        self.sio = socketio.Client()
        self.setup_socketio_events()
        
        # Create UI
        self.create_ui()
        
        # Start socket.io in background
        threading.Thread(target=self.start_socketio, daemon=True).start()
        
        # Show start screen
        self.show_start_screen()
        self.render_friends()

    def load_pinned_messages(self):
        """Load pinned messages from database"""
        try:
            if self.active_friend:
                self.cursor.execute("""
                    SELECT message FROM pinned_messages 
                    WHERE (pinned_by = %s AND conversation_with = %s)
                    OR (pinned_by = %s AND conversation_with = %s)
                """, (
                    self.controller.username, self.active_friend,
                    self.active_friend, self.controller.username
                ))
                self.pinned_messages = [row["message"] for row in self.cursor.fetchall()]
        except Exception as e:
            print(f"Error loading pinned messages: {e}")
            self.pinned_messages = []

    def pin_message(self, message):
        if message not in self.pinned_messages:
            try:
                # Save to database
                self.cursor.execute("""
                    INSERT INTO pinned_messages (message, pinned_by, conversation_with)
                    VALUES (%s, %s, %s)
                """, (message, self.controller.username, self.active_friend))
                self.conn.commit()
                
                # Add to local list
                self.pinned_messages.append(message)
                self.show_pin_notification(message)
                self.render_messages()
            except Exception as e:
                print(f"Error pinning message: {e}")
                messagebox.showerror("Error", f"Failed to pin message: {str(e)}")

    def unpin_message(self, message, popup=None):
        if message in self.pinned_messages:
            try:
                # Remove from database
                self.cursor.execute("""
                    DELETE FROM pinned_messages 
                    WHERE message = %s 
                    AND (pinned_by = %s OR conversation_with = %s)
                """, (message, self.controller.username, self.controller.username))
                self.conn.commit()
                
                # Remove from local list
                self.pinned_messages.remove(message)
                self.render_messages()
                if popup:
                    popup.destroy()
            except Exception as e:
                print(f"Error unpinning message: {e}")
                messagebox.showerror("Error", f"Failed to unpin message: {str(e)}")

    def set_active_friend(self, name):
        self.active_friend = name
        self.unread_messages[name] = 0
        self.load_pinned_messages()  # Load pinned messages for this conversation
        self.show_chat_ui()
        self.render_messages()

    def create_messages_table(self):
        try:
            self.cursor.execute("""
                CREATE TABLE IF NOT EXISTS messages (
                    id SERIAL PRIMARY KEY,
                    sender VARCHAR(100) NOT NULL,
                    recipient VARCHAR(100) NOT NULL,
                    content TEXT NOT NULL,
                    sent_at TIMESTAMP NOT NULL DEFAULT NOW(),
                    reply_to TEXT
                )
            """)
            self.conn.commit()
        except Exception as e:
            print(f"Error creating messages table: {e}")
            self.conn.rollback()
            self.reconnect_db()

    def reconnect_db(self):
        try:
            if self.conn:
                self.conn.close()
            self.conn = psycopg2.connect(**self.db_config)
            self.cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        except Exception as e:
            print(f"Error reconnecting to database: {e}")

    def load_message_history(self):
        try:
            # Get all messages where user is either sender or recipient
            self.cursor.execute("""
                SELECT sender, recipient, content, sent_at, reply_to
                FROM messages
                WHERE sender = %s OR recipient = %s
                ORDER BY sent_at ASC
            """, (self.controller.username, self.controller.username))
            
            messages = self.cursor.fetchall()
            
            # Dictionary to track last message timestamp for each conversation
            last_message_time = {}
            
            # Populate conversations dictionary
            for msg in messages:
                other_user = msg['recipient'] if msg['sender'] == self.controller.username else msg['sender']
                if other_user not in self.conversations:
                    self.conversations[other_user] = []
                    self.unread_messages[other_user] = 0
                
                message_text = msg['content']
                if msg['reply_to']:
                    message_text = f"↩️ Replying to: {msg['reply_to']}\n\n{message_text}"
                
                # Format timestamp to include date and time
                timestamp = msg['sent_at'].strftime("%Y-%m-%d %H:%M:%S")
                
                self.conversations[other_user].append(
                    (msg['sender'], message_text, timestamp)
                )
                
                # Update last message timestamp for this conversation
                last_message_time[other_user] = msg['sent_at']
            
            # Sort user_data based on last message timestamp
            sorted_users = sorted(
                last_message_time.keys(),
                key=lambda x: last_message_time[x],
                reverse=True  # Most recent first
            )
            
            # Create new ordered dictionaries
            new_user_data = {k: self.user_data[k] for k in sorted_users if k in self.user_data}
            # Add any remaining users who haven't had conversations yet
            for k in self.user_data:
                if k not in new_user_data:
                    new_user_data[k] = self.user_data[k]
            
            new_conversations = {k: self.conversations[k] for k in sorted_users if k in self.conversations}
            new_unread_messages = {k: self.unread_messages[k] for k in sorted_users if k in self.unread_messages}
            
            # Update the dictionaries
            self.user_data = new_user_data
            self.conversations = new_conversations
            self.unread_messages = new_unread_messages
        
        except Exception as e:
            print(f"Error loading message history: {e}")
            self.conn.rollback()
            self.reconnect_db()

    def save_message_to_db(self, sender, recipient, message, reply_to=None):
        max_retries = 3
        retry_count = 0
        
        while retry_count < max_retries:
            try:
                # Start a new transaction
                if self.conn.closed:
                    self.reconnect_db()
                
                # Get current timestamp in proper format
                current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                
                self.cursor.execute("""
                    INSERT INTO messages (sender, recipient, content, sent_at, reply_to)
                    VALUES (%s, %s, %s, %s, %s)
                """, (sender, recipient, message, current_time, reply_to))
                
                self.conn.commit()
                return True  # Successfully saved
                
            except psycopg2.Error as e:
                print(f"Database error (attempt {retry_count + 1}/{max_retries}): {e}")
                self.conn.rollback()  # Rollback the failed transaction
                
                if "current transaction is aborted" in str(e):
                    self.reconnect_db()  # Reconnect to start fresh
                
                retry_count += 1
                if retry_count < max_retries:
                    time.sleep(0.5)  # Wait before retrying
            
            except Exception as e:
                print(f"Unexpected error saving message: {e}")
                self.conn.rollback()
                return False
        
        print("Failed to save message after maximum retries")
        return False

    def fetch_friends(self):
        self.cursor.execute('SELECT username, firstname, lastname FROM login WHERE username != %s;', (self.controller.username,))
        rows = self.cursor.fetchall()
        users = {r["username"]: f"{r['firstname']} {r['lastname']}" for r in rows}
        
        # Initialize conversations and unread_messages for all users
        for username in users:
            if username not in self.conversations:
                self.conversations[username] = []
            if username not in self.unread_messages:
                self.unread_messages[username] = 0
        
        return users

    def create_ui(self):
        # Create sidebar
        self.sidebar = ctk.CTkFrame(self, width=300, fg_color="#1E1E1E")
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)
        
        # Top frame with search
        self.create_top_frame()
        
        # Friends list
        self.friends_frame = ctk.CTkScrollableFrame(self.sidebar, fg_color="#1E1E1E")
        self.friends_frame.pack(padx=5, pady=5, fill="both", expand=True)
        self.friends_frame._scrollbar.configure(width=10)
        
        # Main chat area
        self.right_frame = ctk.CTkFrame(self, fg_color="#131313")
        self.right_frame.pack(side="right", fill="both", expand=True)
        
        self.chat_area = None
        self.message_entry = None
        self.option_menus = []

    def create_top_frame(self):
        # Top frame
        top_frame = ctk.CTkFrame(self.sidebar, fg_color="#1E1E1E", height=120)
        top_frame.pack(fill="x")
        top_frame.pack_propagate(False)
        
        # Chat title with icon
        title_frame = ctk.CTkFrame(top_frame, fg_color="transparent")
        title_frame.pack(padx=20, pady=(20,10), fill="x")
        
        chat_icon = ctk.CTkImage(
            Image.open("/home/zalma/Downloads/watchtower/watchtower/icons/chat.png"),
            size=(24, 24)
        )
        ctk.CTkLabel(title_frame, image=chat_icon, text="").pack(side="left", padx=(0,10))
        ctk.CTkLabel(
            title_frame,
            text="Messages",
            font=("Arial", 20, "bold"),
            text_color="white"
        ).pack(side="left")
        
        # Search frame
        self.search_var = ctk.StringVar()
        search_frame = ctk.CTkFrame(top_frame, fg_color="#2C2C2C", height=40)
        search_frame.pack(padx=15, pady=(0,15), fill="x")
        search_frame.pack_propagate(False)
        
        search_icon = ctk.CTkImage(
            Image.open("/home/zalma/Downloads/watchtower/watchtower/icons/search.png"),
            size=(16, 16)
        )
        
        ctk.CTkLabel(search_frame, image=search_icon, text="").pack(side="left", padx=10)
        ctk.CTkEntry(
            search_frame,
            placeholder_text="Search messages...",
            placeholder_text_color="#808080",
            textvariable=self.search_var,
            fg_color="#2C2C2C",
            border_width=0,
            font=("Arial", 13),
            text_color="white"
        ).pack(side="left", fill="both", expand=True, padx=(0,10), pady=5)
        
        self.search_var.trace_add("write", lambda *a: self.render_friends())

    def setup_socketio_events(self):
        @self.sio.event
        def connect():
            print("🔌 Connected to server")
            self.sio.emit('login', {'username': self.controller.username})

        @self.sio.event
        def chat_history(data):
            for msg in data['history']:
                sender = msg['from']
                recipient = msg['to']
                content = msg['content']
                ts = msg['timestamp']
                reply_to = msg.get('reply_to')
                
                other = recipient if sender == self.controller.username else sender
                if other not in self.conversations:
                    self.conversations[other] = []
                    self.unread_messages[other] = 0
                
                message_text = content
                if reply_to:
                    message_text = f"↩️ Replying to: {reply_to}\n\n{content}"
                
                self.conversations[other].append((sender, message_text, ts))
            
            self.after(0, self.render_friends)
            if self.active_friend:
                self.after(0, self.render_messages)

        @self.sio.event
        def new_message(data):
            sender = data['from']
            recipient = data['to']
            content = data['content']
            ts = data['timestamp']
            reply_to = data.get('reply_to')
            
            other = sender if sender != self.controller.username else recipient
            if other not in self.conversations:
                self.conversations[other] = []
                self.unread_messages[other] = 0
                self.after(0, self.render_friends)
            
            message_text = content
            if reply_to:
                message_text = f"↩️ Replying to: {reply_to}\n\n{content}"
            
            self.conversations[other].append((sender, message_text, ts))
            if sender != self.controller.username:
                self.unread_messages[other] += 1
            
            if self.active_friend == other:
                self.after(0, self.render_messages)
                self.unread_messages[other] = 0

    def start_socketio(self):
        try:
            self.sio.connect('http://localhost:5000', wait_timeout=10)
            print("✅ Connected to chat server")
        except Exception as e:
            print(f"⚠️ Could not connect to chat server: {e}")

    def show_start_screen(self):
        for w in self.right_frame.winfo_children():
            w.destroy()
        
        start_icon = ctk.CTkImage(
            Image.open("/home/zalma/Downloads/watchtower/watchtower/icons/chatIcon.png"),
            size=(120, 120)
        )
        
        lbl = ctk.CTkLabel(self.right_frame, image=start_icon, text="", fg_color="#131313")
        lbl.image = start_icon
        lbl.place(relx=0.5, rely=0.4, anchor="center")
        
        ctk.CTkLabel(
            self.right_frame,
            text="No chat selected",
            text_color="#AEAEAE",
            font=("Arial", 16),
            fg_color="#131313"
        ).place(relx=0.5, rely=0.55, anchor="center")

    def render_friends(self):
        # Clear existing friends
        for widget in self.friends_frame.winfo_children():
            widget.destroy()
        
        # If no user data, show appropriate message
        if not self.user_data:
            ctk.CTkLabel(
                self.friends_frame,
                text="No contacts available\nPlease check database connection",
                font=("Arial", 14),
                text_color="#808080",
                justify="center"
            ).pack(pady=20)
            return
        
        search_text = self.search_var.get().lower()
        
        for username, full_name in self.user_data.items():
            if search_text and search_text not in full_name.lower() and search_text not in username.lower():
                continue
                
            self.create_friend_row(username)

    def create_friend_row(self, username):
        full_name = self.user_data[username]
        
        # Make the entire row even taller and add padding
        row = ctk.CTkFrame(self.friends_frame, height=100, fg_color="#1E1E1E")  # Reduced height
        row.pack(fill="x", pady=(0,8))
        row.pack_propagate(False)
        
        # Create a clickable overlay that covers the entire row
        overlay = ctk.CTkFrame(row, fg_color="transparent")
        overlay.place(relx=0, rely=0, relwidth=1, relheight=1)
        
        def on_enter(e):
            if self.active_friend != username:
                row.configure(fg_color="#2C2C2C")
                overlay.configure(cursor="hand2")
            
        def on_leave(e):
            if self.active_friend != username:
                row.configure(fg_color="#1E1E1E")
                overlay.configure(cursor="")
        
        # Bind events to both the row and overlay
        for widget in (row, overlay):
            widget.bind("<Enter>", on_enter)
            widget.bind("<Leave>", on_leave)
            widget.bind("<Button-1>", lambda e, u=username: self.set_active_friend(u))
        
        # Avatar frame - made smaller
        avatar_frame = ctk.CTkFrame(row, width=50, height=50, fg_color="#2C2C2C", corner_radius=25)  # Reduced size
        avatar_frame.pack(side="left", padx=(20,15), pady=25)  # Adjusted padding
        avatar_frame.pack_propagate(False)
        
        # Avatar icon - made smaller
        friend_icon = ctk.CTkImage(
            Image.open("/home/zalma/Downloads/watchtower/watchtower/icons/user.png").resize((30, 30), Image.Resampling.LANCZOS),
            size=(30, 30)  # Reduced icon size
        )
        ctk.CTkLabel(avatar_frame, image=friend_icon, text="").pack(expand=True)
        
        # Info frame with more padding
        info_frame = ctk.CTkFrame(row, fg_color="transparent")
        info_frame.pack(side="left", fill="both", expand=True, pady=15, padx=(0,15))  # Adjusted padding
        
        # Name and status
        name_frame = ctk.CTkFrame(info_frame, fg_color="transparent")
        name_frame.pack(fill="x", pady=(5,0))  # Reduced top padding
        
        ctk.CTkLabel(
            name_frame,
            text=full_name,
            font=("Arial", 16, "bold"),  # Slightly smaller font
            text_color="white"
        ).pack(side="left")
        
        # Ensure unread_messages is initialized for this user
        if username not in self.unread_messages:
            self.unread_messages[username] = 0
            
        if self.unread_messages[username] > 0:
            unread_frame = ctk.CTkFrame(name_frame, width=20, height=20, fg_color="#4CAF50", corner_radius=10)  # Smaller badge
            unread_frame.pack(side="right", padx=10)
            unread_frame.pack_propagate(False)
            
            ctk.CTkLabel(
                unread_frame,
                text=str(self.unread_messages[username]),
                font=("Arial", 10, "bold"),  # Smaller font
                text_color="white"
            ).pack(expand=True)
        
        # Last message preview if any
        if username in self.conversations and self.conversations[username]:
            last_msg = self.conversations[username][-1]
            preview = last_msg[1][:30] + "..." if len(last_msg[1]) > 30 else last_msg[1]
            ctk.CTkLabel(
                info_frame,
                text=preview,
                font=("Arial", 12),
                text_color="#808080"
            ).pack(fill="x")
        
        if self.active_friend == username:
            row.configure(fg_color="#2C2C2C")
        
        row.bind("<Button-1>", lambda e, u=username: self.set_active_friend(u))

    def show_chat_ui(self):
        # Clear right frame
        for w in self.right_frame.winfo_children():
            w.destroy()
        
        # Chat header
        header = ctk.CTkFrame(self.right_frame, height=100, fg_color="#1A1A1A")
        header.pack(fill="x")
        header.pack_propagate(False)
        
        # Title container with pinned messages button
        title_container = ctk.CTkFrame(header, fg_color="#1A1A1A", height=100)
        title_container.pack(fill="x", padx=30)
        title_container.pack_propagate(False)
        
        # Left side - Title
        ctk.CTkLabel(
            title_container,
            text=self.user_data[self.active_friend],
            font=("Arial", 24, "bold"),
            text_color="white"
        ).pack(side="left", pady=30)
        
        # Right side - Pinned messages button
        pin_btn = ctk.CTkButton(
            title_container,
            text="📌 Pinned Messages",
            font=("Arial", 14),
            fg_color="#2C2C2C",
            hover_color="#3E3E3E",
            command=self.show_pinned_messages
        )
        pin_btn.pack(side="right", pady=30, padx=10)
        
        # Chat area
        self.chat_area = ctk.CTkScrollableFrame(
            self.right_frame,
            fg_color="#131313"
        )
        self.chat_area.pack(fill="both", expand=True, padx=2)
        
        # Message input area with reply preview
        input_container = ctk.CTkFrame(self.right_frame, fg_color="#1A1A1A")
        input_container.pack(fill="x", side="bottom")
        
        # Reply preview frame (initially hidden)
        self.reply_frame = ctk.CTkFrame(input_container, fg_color="#1A1A1A", height=0)
        self.reply_frame.pack(fill="x")
        
        # Message input frame
        input_frame = ctk.CTkFrame(input_container, height=100, fg_color="#1A1A1A")
        input_frame.pack(fill="x")
        input_frame.pack_propagate(False)
        
        # Message box
        message_box_frame = ctk.CTkFrame(input_frame, fg_color="#2C2C2C", corner_radius=20)
        message_box_frame.pack(fill="x", padx=20, pady=20)
        
        self.message_entry = ctk.CTkTextbox(
            message_box_frame,
            height=40,
            fg_color="#2C2C2C",
            border_width=0,
            font=("Arial", 14),
            text_color="white"
        )
        self.message_entry.pack(side="left", fill="x", expand=True, padx=(20,10), pady=10)
        
        # Buttons frame
        button_frame = ctk.CTkFrame(message_box_frame, fg_color="transparent")
        button_frame.pack(side="right", padx=10)
        
        # Attachment button
        file_icon = ctk.CTkImage(
            Image.open("/home/zalma/Downloads/watchtower/watchtower/icons/file.png"),
            size=(20, 20)
        )
        ctk.CTkButton(
            button_frame,
            text="",
            image=file_icon,
            width=40,
            height=40,
            fg_color="transparent",
            hover_color="#3E3E3E",
            corner_radius=20,
            command=self.send_file
        ).pack(side="left", padx=5)
        
        # Send button
        send_icon = ctk.CTkImage(
            Image.open("/home/zalma/Downloads/watchtower/watchtower/icons/send.png"),
            size=(20, 20)
        )
        ctk.CTkButton(
            button_frame,
            text="",
            image=send_icon,
            width=40,
            height=40,
            fg_color="#1976D2",
            hover_color="#1565C0",
            corner_radius=20,
            command=self.send_message
        ).pack(side="left", padx=5)

    def show_pinned_messages(self):
        # Create popup window
        popup = tk.Toplevel(self)
        popup.title("Pinned Messages")
        popup.geometry("400x600")
        popup.configure(bg="#1A1A1A")
        
        # Create scrollable frame for pinned messages
        container = ctk.CTkFrame(popup, fg_color="#1A1A1A")
        container.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Title
        ctk.CTkLabel(
            container,
            text="📌 Pinned Messages",
            font=("Arial", 20, "bold"),
            text_color="white"
        ).pack(pady=(0,20))
        
        # Scrollable frame for messages
        messages_frame = ctk.CTkScrollableFrame(container, fg_color="#1A1A1A")
        messages_frame.pack(fill="both", expand=True)
        
        # Show pinned messages
        for msg in self.pinned_messages:
            msg_frame = ctk.CTkFrame(messages_frame, fg_color="#2C2C2C", corner_radius=10)
            msg_frame.pack(fill="x", pady=5, padx=10)
            
            content = ctk.CTkFrame(msg_frame, fg_color="transparent")
            content.pack(fill="x", padx=15, pady=10)
            
            # Message text
            ctk.CTkLabel(
                content,
                text=msg,
                font=("Arial", 14),
                text_color="white",
                justify="left",
                wraplength=300
            ).pack(anchor="w")
            
            # Unpin button
            ctk.CTkButton(
                content,
                text="Unpin",
                font=("Arial", 12),
                fg_color="#1976D2",
                hover_color="#1565C0",
                width=60,
                height=25,
                command=lambda m=msg: self.unpin_message(m, popup)
            ).pack(anchor="e", pady=(5,0))

    def reply_to_message(self, message):
        self.replying_to = message
        
        # Clear any existing reply frame content
        if hasattr(self, 'reply_frame'):
            for widget in self.reply_frame.winfo_children():
                widget.destroy()
        
        # Configure reply frame with improved style
        self.reply_frame.configure(height=65, fg_color="#1E1E1E")
        self.reply_frame.pack(fill="x", padx=20, pady=(5,0))
        
        # Create inner frame for better visual separation
        inner_frame = ctk.CTkFrame(self.reply_frame, fg_color="#2C2C2C", corner_radius=8)
        inner_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Left border to indicate reply
        border = ctk.CTkFrame(inner_frame, width=3, fg_color="#1976D2")
        border.pack(side="left", fill="y", padx=(5,0), pady=5)
        
        # Reply content
        reply_content = ctk.CTkFrame(inner_frame, fg_color="transparent")
        reply_content.pack(fill="x", expand=True, padx=(10,15), pady=5)
        
        # Header frame for "Replying to" and sender name
        header_frame = ctk.CTkFrame(reply_content, fg_color="transparent")
        header_frame.pack(fill="x")
        
        ctk.CTkLabel(
            header_frame,
            text="↩️ Replying to",
            font=("Arial", 12),
            text_color="#808080"
        ).pack(side="left")
        
        # Original sender name (if not self)
        if not message.startswith(self.controller.username):
            ctk.CTkLabel(
                header_frame,
                text=f" {self.user_data.get(self.active_friend, self.active_friend)}",
                font=("Arial", 12, "bold"),
                text_color="#1976D2"
            ).pack(side="left")
        
        # Message preview
        preview = message[:50] + "..." if len(message) > 50 else message
        self.reply_preview = ctk.CTkLabel(
            reply_content,
            text=preview,
            font=("Arial", 12),
            text_color="#E0E0E0",
            justify="left",
            wraplength=400
        )
        self.reply_preview.pack(anchor="w", pady=(5,0))
        
        # Cancel button
        cancel_btn = ctk.CTkButton(
            inner_frame,
            text="×",
            width=24,
            height=24,
            fg_color="#3E3E3E",
            hover_color="#4E4E4E",
            text_color="white",
            font=("Arial", 16, "bold"),
            corner_radius=12,
            command=self.cancel_reply
        )
        cancel_btn.pack(side="right", padx=10)
        
        # Focus the message entry
        self.message_entry.focus_set()

    def render_messages(self):
        if not self.chat_area:
            return
            
        for widget in self.chat_area.winfo_children():
            widget.destroy()
            
        messages = self.conversations.get(self.active_friend, [])
        current_date = None
        
        for i, (sender, text, timestamp) in enumerate(messages):
            # Convert timestamp to datetime
            try:
                msg_datetime = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                try:
                    msg_datetime = datetime.strptime(timestamp, "%I:%M %p")
                    msg_datetime = msg_datetime.replace(year=datetime.now().year, 
                                                      month=datetime.now().month, 
                                                      day=datetime.now().day)
                except ValueError:
                    msg_datetime = datetime.now()
            
            # Check if we need to show a new date header
            msg_date = msg_datetime.date()
            if msg_date != current_date:
                current_date = msg_date
                
                # Create date header
                date_container = ctk.CTkFrame(self.chat_area, fg_color="transparent")
                date_container.pack(fill="x", pady=10)
                
                # Format date header text
                if msg_date == datetime.now().date():
                    date_text = "Today"
                elif msg_date == (datetime.now() - timedelta(days=1)).date():
                    date_text = "Yesterday"
                else:
                    date_text = msg_datetime.strftime("%B %d, %Y")
                
                # Add date header
                date_label = ctk.CTkLabel(
                    date_container,
                    text=date_text,
                    font=("Arial", 12),
                    text_color="#808080",
                    fg_color="#2C2C2C",
                    corner_radius=10
                )
                date_label.pack(pady=5)
            
            is_self = sender == self.controller.username
            
            # Message container
            msg_container = ctk.CTkFrame(self.chat_area, fg_color="transparent")
            msg_container.pack(fill="x", pady=5)
            
            # Create a frame to hold message bubble and options button
            msg_with_options = ctk.CTkFrame(msg_container, fg_color="transparent")
            msg_with_options.pack(side="right" if is_self else "left", padx=20)
            
            if is_self:
                options_btn = self.create_message_options(msg_with_options, text)
                options_btn.pack(side="left", padx=5)
                
                msg_frame = ctk.CTkFrame(
                    msg_with_options,
                    fg_color="#1976D2" if is_self else "#2C2C2C",
                    corner_radius=15
                )
                msg_frame.pack(side="right")
            else:
                msg_frame = ctk.CTkFrame(
                    msg_with_options,
                    fg_color="#1976D2" if is_self else "#2C2C2C",
                    corner_radius=15
                )
                msg_frame.pack(side="left")
                
                options_btn = self.create_message_options(msg_with_options, text)
                options_btn.pack(side="right", padx=5)
            
            # Message content
            content_frame = ctk.CTkFrame(msg_frame, fg_color="transparent")
            content_frame.pack(side="left", padx=15, pady=10)
            
            # Check if this is a reply message
            if "↩️" in text:
                # Split the message into reply preview and actual message
                parts = text.split("\n\n", 1)
                if len(parts) == 2:
                    reply_text, actual_message = parts
                    
                    # Create reply preview frame
                    reply_preview = ctk.CTkFrame(content_frame, fg_color="#1E1E1E", corner_radius=5)
                    reply_preview.pack(fill="x", pady=(0, 5))
                    
                    # Add reply preview content
                    ctk.CTkLabel(
                        reply_preview,
                        text=reply_text,
                        font=("Arial", 11),
                        text_color="#808080",
                        justify="left"
                    ).pack(anchor="w", padx=8, pady=5)
                    
                    # Set the actual message text
                    text = actual_message
            
            # Pin indicator if message is pinned
            if text in self.pinned_messages:
                pin_frame = ctk.CTkFrame(content_frame, fg_color="transparent")
                pin_frame.pack(fill="x", pady=(0, 5))
                ctk.CTkLabel(
                    pin_frame,
                    text="📌 Pinned",
                    font=("Arial", 10),
                    text_color="#1976D2"
                ).pack(anchor="w")
            
            # Sender name
            if not is_self:
                ctk.CTkLabel(
                    content_frame,
                    text=self.user_data[sender],
                    font=("Arial", 12, "bold"),
                    text_color="#808080"
                ).pack(anchor="w")
            
            # Message text
            msg_label = ctk.CTkLabel(
                content_frame,
                text=text,
                font=("Arial", 14),
                text_color="white",
                justify="left",
                wraplength=400
            )
            msg_label.pack(anchor="w")
            
            # Format time for display
            time_text = msg_datetime.strftime("%I:%M %p")
            
            # Timestamp
            time_label = ctk.CTkLabel(
                content_frame,
                text=time_text,
                font=("Arial", 10),
                text_color="#FFFFFF" if is_self else "#606060"
            )
            time_label.pack(anchor="e", pady=(5,0))
            
            # Store message index for potential reply scrolling
            msg_frame.message_index = i
            
            # Make reply preview clickable to scroll to original message
            if "↩️" in text:
                msg_frame.bind("<Button-1>", lambda e, idx=i: self.scroll_to_message(idx))
                msg_frame.configure(cursor="hand2")
        
        # After rendering all messages, scroll to the bottom
        self.chat_area._parent_canvas.yview_moveto(1.0)

    def scroll_to_message(self, index):
        # Get all message frames
        message_frames = [widget for widget in self.chat_area.winfo_children() 
                         if isinstance(widget, ctk.CTkFrame)]
        
        # Find the original message and scroll to it
        if 0 <= index < len(message_frames):
            target_frame = message_frames[index]
            
            # Temporarily highlight the message
            original_color = target_frame.cget("fg_color")
            target_frame.configure(fg_color="#2C3E50")
            
            # Calculate position to scroll
            canvas = self.chat_area._scrollbar_frame._parent_canvas
            frame_y = target_frame.winfo_y()
            canvas.yview_moveto(frame_y / canvas.winfo_height())
            
            # Reset color after a delay
            self.after(1000, lambda: target_frame.configure(fg_color=original_color))

    def send_message(self, event=None):
        if not self.message_entry or not self.active_friend:
            return
            
        message = self.message_entry.get("1.0", "end-1c").strip()
        if not message:
            return
            
        timestamp = datetime.now().strftime("%I:%M %p")
        original_message = message
        
        # Create message data
        message_data = {
            'from': self.controller.username,
            'to': self.active_friend,
            'content': message,
            'timestamp': timestamp
        }
        
        # Add reply information if replying
        if self.replying_to:
            message_data['reply_to'] = self.replying_to
            # Format message with reply preview
            message = f"↩️ {self.replying_to}\n\n{message}"
        
        self.sio.emit('message', message_data)
        
        # Save message to database
        self.save_message_to_db(
            self.controller.username,
            self.active_friend,
            original_message,
            self.replying_to
        )
        
        self.message_entry.delete("1.0", "end")
        
        # Move this contact to the top of the list
        self.move_contact_to_top(self.active_friend)
        
        # Clear reply state
        if self.replying_to:
            self.cancel_reply()

    def move_contact_to_top(self, username):
        # Get the current order of friends
        friends = list(self.user_data.keys())
        if username in friends:
            friends.remove(username)
            friends.insert(0, username)
            
            # Create new ordered dictionaries
            new_user_data = {k: self.user_data[k] for k in friends}
            new_conversations = {}
            new_unread_messages = {}
            
            # Safely copy conversations and unread messages
            for k in friends:
                new_conversations[k] = self.conversations.get(k, [])
                new_unread_messages[k] = self.unread_messages.get(k, 0)
            
            # Update the dictionaries
            self.user_data = new_user_data
            self.conversations = new_conversations
            self.unread_messages = new_unread_messages

    def send_file(self):
        if not self.active_friend:
            return
            
        file_path = filedialog.askopenfilename()
        if not file_path:
            return
            
        file_name = os.path.basename(file_path)
        timestamp = datetime.now().strftime("%I:%M %p")
        
        self.sio.emit('message', {
            'from': self.controller.username,
            'to': self.active_friend,
            'content': f"📎 Sent file: {file_name}",
            'timestamp': timestamp,
            'file': file_path
        })
        
        self.conversations[self.active_friend].append(
            (self.controller.username, f"📎 Sent file: {file_name}", timestamp)
        )
        self.render_messages()

    def create_message_options(self, msg_with_options, message_text):
        def show_options(event=None):
            # Get the button widget that was clicked
            button = event.widget if event else msg_with_options.winfo_children()[-1]
            
            # Create options menu
            menu = tk.Menu(msg_with_options, tearoff=0, bg="#2C2C2C", fg="white", 
                         activebackground="#3E3E3E", activeforeground="white")
            menu.add_command(label="Copy", command=lambda: self.copy_message(message_text))
            menu.add_command(label="Pin Message", command=lambda: self.pin_message(message_text))
            menu.add_command(label="Reply", command=lambda: self.reply_to_message(message_text))
            
            # Get button position
            x = button.winfo_rootx()
            y = button.winfo_rooty() + button.winfo_height()
            
            # Show menu at button position
            menu.tk_popup(x, y)
        
        # Create options button
        options_btn = ctk.CTkButton(
            msg_with_options,
            text="⋮",
            width=20,
            height=20,
            fg_color="transparent",
            hover_color="#3E3E3E",
            text_color="#808080",
            font=("Arial", 16)
        )
        options_btn.bind("<Button-1>", show_options)
        return options_btn

    def copy_message(self, message):
        self.clipboard_clear()
        self.clipboard_append(message)
    
    def cancel_reply(self):
        if hasattr(self, 'reply_frame'):
            self.reply_frame.pack_forget()
            self.replying_to = None

    def show_pin_notification(self, message):
        # Create notification window
        notification = tk.Toplevel(self)
        notification.configure(bg="#2C2C2C")
        notification.overrideredirect(True)
        
        # Position notification at top of chat area
        x = self.winfo_rootx() + self.winfo_width() - 300
        y = self.winfo_rooty() + 100
        notification.geometry(f"250x60+{x}+{y}")
        
        # Add notification content
        frame = ctk.CTkFrame(notification, fg_color="#2C2C2C")
        frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        ctk.CTkLabel(
            frame,
            text="Message Pinned",
            font=("Arial", 14, "bold"),
            text_color="white"
        ).pack(anchor="w")
        
        preview = message[:30] + "..." if len(message) > 30 else message
        ctk.CTkLabel(
            frame,
            text=preview,
            font=("Arial", 12),
            text_color="#808080"
        ).pack(anchor="w")
        
        # Auto-close notification after 2 seconds
        self.after(2000, notification.destroy)

class HomeFrame(ctk.CTkFrame):
    def __init__(self, parent, controller):
        super().__init__(parent, fg_color="#131313")
        self.controller = controller
        
        # Set up background image
        self.setup_background()
        
        # Ensure announcements table has admin_username column
        self.setup_announcements_table()
        
        # Set up announcements
        self.setup_announcements_ui()
    
    def setup_announcements_table(self):
        try:
            conn = psycopg2.connect(**self.controller.db_config)
            cursor = conn.cursor()
            
            # Check if admin_username column exists
            cursor.execute("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name='announcements' AND column_name='admin_username';
            """)
            
            if not cursor.fetchone():
                # Add admin_username column if it doesn't exist
                cursor.execute("""
                    ALTER TABLE announcements 
                    ADD COLUMN admin_username VARCHAR(100) REFERENCES login(username);
                """)
                conn.commit()
            
            cursor.close()
            conn.close()
        except Exception as e:
            print(f"Database error setting up announcements table: {e}")
    
    def setup_background(self):
        # Define background paths based on user role
        admin_bg_path = "/home/zalma/Downloads/watchtower/watchtower/icons/admin_bg.png"
        user_bg_path = "/home/zalma/Downloads/watchtower/watchtower/icons/user_bg.png"
        
        # Select background based on user role
        bg_img_path = admin_bg_path if self.controller.user_role == "admin" else user_bg_path
        
        # Load and resize background image
        self.bg_img = Image.open(bg_img_path)
        
        def resize_bg(event=None):
            if event:
                # Resize image to fit the frame
                resized = Image.open(bg_img_path).resize((event.width, event.height))
                self.bg_photo = ImageTk.PhotoImage(resized)
                self.bg_label.configure(image=self.bg_photo)
                self.bg_label.image = self.bg_photo
        
        self.bind("<Configure>", resize_bg)
        
        # Create initial background
        self.bg_photo = ImageTk.PhotoImage(self.bg_img)
        self.bg_label = tk.Label(self, image=self.bg_photo)
        self.bg_label.image = self.bg_photo
        self.bg_label.place(x=0, y=0, relwidth=1, relheight=1)
    
    def setup_announcements_ui(self):
        # Create two separate frames - one for viewing at top
        view_frame = ctk.CTkFrame(self, fg_color="transparent", height=200)
        view_frame.pack(side="top", fill="x", padx=10, pady=10)
        
        # Title
        title_label = ctk.CTkLabel(
            view_frame,
            text="Announcements",
            font=("Arial", 24, "bold"),
            text_color="#FFFFFF",
            anchor="w"
        )
        title_label.pack(fill="x", pady=(0, 15))
        
        # Box frame for announcements list
        list_box_frame = ctk.CTkFrame(
            view_frame,
            fg_color="#1E1E1E",
            corner_radius=10,
            border_width=1,
            border_color="#3A3A3A",
            height=150
        )
        list_box_frame.pack(fill="both", expand=True, pady=(0, 15))
        
        # Scrollable announcements list
        self.scroll_frame = ctk.CTkScrollableFrame(
            list_box_frame,
            fg_color="#1E1E1E"
        )
        self.scroll_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Text widget for announcements
        self.announcements_text = tk.Text(
            self.scroll_frame,
            bg="#1E1E1E",
            fg="white",
            wrap="word",
            font=("Arial", 14),
            padx=10,
            pady=10,
            borderwidth=0,
            highlightthickness=0,
            selectbackground="#3A3A3A"
        )
        self.announcements_text.pack(fill="both", expand=True)
        
        # Configure text tags
        self.announcements_text.tag_configure("timestamp", foreground="#7FDBFF", font=("Arial", 12, "bold"))
        self.announcements_text.tag_configure("message", foreground="white", font=("Arial", 14))
        self.announcements_text.tag_configure("admin_name", foreground="gray", font=("Arial", 14, "italic"))
        self.announcements_text.tag_configure("clickable", spacing3=5)
        self.announcements_text.tag_configure("selected", background="#3A3A3A")
        
        self.selected_id = None  # track selected announcement id
        
        # ADMIN-ONLY CONTROLS
        if self.controller.user_role == "admin":
            edit_frame = ctk.CTkFrame(self, fg_color="transparent", height=200)
            edit_frame.pack(side="bottom", fill="x", padx=10, pady=10)
            
            edit_section = ctk.CTkFrame(edit_frame, fg_color="transparent")
            edit_section.pack(fill="x", pady=(10, 0))
            
            edit_label = ctk.CTkLabel(
                edit_section,
                text="Manage Announcements",
                font=("Arial", 20, "bold"),
                text_color="#FFFFFF",
                anchor="w"
            )
            edit_label.pack(fill="x", pady=(0, 5))
            
            text_frame = ctk.CTkFrame(
                edit_section,
                fg_color="#1E1E1E",
                corner_radius=8,
                border_width=1,
                border_color="#3A3A3A"
            )
            text_frame.pack(fill="x", pady=(0, 10))
            
            self.edit_text = ctk.CTkTextbox(
                text_frame,
                fg_color="#1E1E1E",
                text_color="white",
                font=("Arial", 14),
                border_width=0,
                wrap="word",
                height=100
            )
            self.edit_text.pack(fill="both", expand=True, padx=5, pady=5)
            
            button_frame = ctk.CTkFrame(edit_section, fg_color="transparent")
            button_frame.pack(fill="x", pady=(5, 0))
            
            save_btn = ctk.CTkButton(
                button_frame,
                text="Send",
                command=self.save_announcement,
                fg_color="#0BA0E3",
                hover_color="#0570a1",
                font=("Arial", 14, "bold"),
                width=100
            )
            save_btn.pack(side="left", padx=(0, 10))
            
            delete_btn = ctk.CTkButton(
                button_frame,
                text="Delete",
                command=self.delete_selected_announcement,
                fg_color="#0BA0E3",
                hover_color="#47010a",
                font=("Arial", 14, "bold"),
                width=100
            )
            delete_btn.pack(side="left", padx=(0, 10))
            
            clear_btn = ctk.CTkButton(
                button_frame,
                text="Clear",
                command=self.clear_selection,
                fg_color="#0BA0E3",
                hover_color="#0570a1",
                font=("Arial", 14, "bold"),
                width=100
            )
            clear_btn.pack(side="left")
            
            # Bind click event for admin
            self.announcements_text.tag_bind("clickable", "<Button-1>", self.on_announcement_click)
        
        # Load announcements
        self.load_announcements()
    
    def clear_selection(self):
        self.selected_id = None
        if self.controller.user_role == "admin":
            self.edit_text.delete("0.0", "end")
        self.announcements_text.tag_remove("selected", "1.0", "end")
    
    def load_announcements(self):
        self.announcements_text.config(state="normal")
        self.announcements_text.delete("1.0", "end")
        
        try:
            conn = psycopg2.connect(**self.controller.db_config)
            cursor = conn.cursor(cursor_factory=RealDictCursor)
            
            # Modified query to join with login table to get admin's first name
            cursor.execute('''
                SELECT a.id, a.message, a.timestamp, a.admin_username, l.firstname 
                FROM announcements a 
                LEFT JOIN login l ON a.admin_username = l.username 
                ORDER BY a.timestamp DESC
            ''')
            anns = cursor.fetchall()
            
            for ann in anns:
                timestamp = f'[{ann["timestamp"].strftime("%Y-%m-%d %H:%M:%S")}]'
                message = ann["message"]
                admin_name = f" - {ann['firstname']}" if ann.get('firstname') else ""
                
                self.announcements_text.insert("end", timestamp + " ", "timestamp")
                self.announcements_text.insert("end", message, "message")
                if admin_name:
                    self.announcements_text.insert("end", admin_name, "admin_name")
                self.announcements_text.insert("end", "\n")
                
                start_idx = self.announcements_text.index(f"end-{len(message + admin_name)+1}c")
                end_idx = self.announcements_text.index("end-1c")
                self.announcements_text.tag_add("clickable", start_idx, end_idx)
                self.announcements_text.tag_add(str(ann["id"]), start_idx, end_idx)
            
            cursor.close()
            conn.close()
            
        except Exception as e:
            print(f"Database error: {e}")
        
        self.announcements_text.config(state="disabled")
    
    def on_announcement_click(self, event):
        index = self.announcements_text.index(f"@{event.x},{event.y}")
        tags = self.announcements_text.tag_names(index)
        announcement_id = next((int(tag) for tag in tags if tag.isdigit()), None)
        
        if announcement_id:
            self.selected_id = announcement_id
            
            self.announcements_text.tag_remove("selected", "1.0", "end")
            self.announcements_text.tag_add("selected", f"{index} linestart", f"{index} lineend")
            
            try:
                conn = psycopg2.connect(**self.controller.db_config)
                cursor = conn.cursor(cursor_factory=RealDictCursor)
                cursor.execute("SELECT message FROM announcements WHERE id = %s", (self.selected_id,))
                result = cursor.fetchone()
                cursor.close()
                conn.close()
                
                if result:
                    self.edit_text.delete("0.0", "end")
                    self.edit_text.insert("0.0", result['message'])
            except Exception as e:
                print(f"Database error: {e}")
    
    def save_announcement(self):
        new_msg = self.edit_text.get("0.0", "end").strip()
        
        if not new_msg:
            return
        
        try:
            conn = psycopg2.connect(**self.controller.db_config)
            cursor = conn.cursor()
            
            if self.selected_id is None:
                cursor.execute(
                    "INSERT INTO announcements (message, admin_username) VALUES (%s, %s)",
                    (new_msg, self.controller.username)
                )
            else:
                cursor.execute(
                    "UPDATE announcements SET message=%s, admin_username=%s WHERE id=%s",
                    (new_msg, self.controller.username, self.selected_id)
                )
            
            conn.commit()
            cursor.close()
            conn.close()
            
            self.edit_text.delete("0.0", "end")
            self.selected_id = None
            self.load_announcements()
            
        except Exception as e:
            print(f"Database error: {e}")
    
    def delete_selected_announcement(self):
        if self.selected_id:
            try:
                conn = psycopg2.connect(**self.controller.db_config)
                cursor = conn.cursor()
                cursor.execute("DELETE FROM announcements WHERE id=%s", (self.selected_id,))
                conn.commit()
                cursor.close()
                conn.close()
                
                self.edit_text.delete("0.0", "end")
                self.selected_id = None
                self.load_announcements()
                
            except Exception as e:
                print(f"Database error: {e}")

class MonitorFrame(ctk.CTkFrame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        
        # Set the color theme
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        # Configure colors
        self.bg_color = "#1a1a1a"  # Dark background
        self.text_color = "#8899AA"  # Soft green
        self.accent_color = "#007acc"  # Blue accent
        self.alert_colors = {
            "high": "#ff3333",    # Red for high severity
            "medium": "#ffa500",  # Orange for medium
            "low": "#ffffff"      # White for low
        }
        
        self.configure(fg_color=self.bg_color)
        
        # Create main container
        self.main_container = ctk.CTkFrame(self, fg_color=self.bg_color)
        self.main_container.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Add status label
        self.status_label = ctk.CTkLabel(self.main_container, 
                                       text="Starting...", 
                                       font=("Arial", 12),
                                       text_color=self.text_color)
        self.status_label.pack(fill="x", padx=10, pady=5)
        
        # Create top frame for controls
        self.controls_frame = ctk.CTkFrame(self.main_container, fg_color=self.bg_color)
        self.controls_frame.pack(fill="x", padx=10, pady=5)
        
        # Create the improved block interface
        self.block_frame = ctk.CTkFrame(self.controls_frame, fg_color=self.bg_color)
        self.block_frame.pack(side="right", padx=5)

        # IP input field with placeholder
        self.ip_entry = ctk.CTkEntry(
            self.block_frame,
            placeholder_text="Enter IP to block (e.g. 192.168.1.1)",
            width=300,
            text_color=self.text_color,
            fg_color="#2d2d2d"
        )
        self.ip_entry.pack(side="left", padx=(10, 5), pady=5)

        # Block button with icon
        self.block_button = ctk.CTkButton(
            self.block_frame,
            text="🛡️ Block IP",
            fg_color="#e74c3c",  # Red color for warning
            hover_color="#c0392b",
            command=self.manual_block_ip
        )
        self.block_button.pack(side="left", padx=5, pady=5)

        # View Blocked IPs button
        self.view_blocked_button = ctk.CTkButton(
            self.block_frame,
            text="View Blocked IPs",
            fg_color="#2980b9",
            hover_color="#2471a3",
            command=self.show_blocked_ips
        )
        self.view_blocked_button.pack(side="left", padx=5, pady=5)

        # Status label
        self.block_status_label = ctk.CTkLabel(
            self.block_frame,
            text="",
            text_color="#95a5a6"
        )
        self.block_status_label.pack(side="left", padx=10)
        
        # Create table
        self.create_table()
        
        # Initialize log monitoring
        self.log_queue = queue.Queue()
        self.should_stop = False
        
        # Create test data if eve.json doesn't exist or is empty
        self.create_test_data()
        
        # Update status
        self.status_label.configure(text="Monitoring logs... Waiting for events.")
        
        # Start monitoring thread
        self.monitor_thread = threading.Thread(target=self.monitor_logs, daemon=True)
        self.monitor_thread.start()
        
        # Start processing the queue
        self.process_log_queue()
        
        # Load blocked IPs from database
        self.load_blocked_ips()

    def load_blocked_ips(self):
        """Load blocked IPs from database"""
        try:
            conn = psycopg2.connect(**self.controller.db_config)
            cursor = conn.cursor()
            
            # Create blocked_ips table if it doesn't exist
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS blocked_ips (
                    id SERIAL PRIMARY KEY,
                    ip_address VARCHAR(45) NOT NULL,
                    blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    blocked_by VARCHAR(100) REFERENCES login(username)
                )
            """)
            conn.commit()
            
            # Debug: Print table schema
            cursor.execute("""
                SELECT column_name, data_type 
                FROM information_schema.columns 
                WHERE table_name = 'blocked_ips';
            """)
            print("Blocked IPs table schema:", cursor.fetchall())
            
            # Debug: Print current records
            cursor.execute("SELECT * FROM blocked_ips")
            print("Current blocked IPs:", cursor.fetchall())
            
            cursor.close()
            conn.close()
        except Exception as e:
            print(f"Error initializing blocked IPs table: {e}")

    def show_blocked_ips(self):
        """Show window with list of blocked IPs"""
        blocked_window = ctk.CTkToplevel(self)
        blocked_window.title("Blocked IPs")
        blocked_window.geometry("600x400")
        blocked_window.configure(fg_color="#1a1a1a")
        
        # Create scrollable frame
        scroll_frame = ctk.CTkScrollableFrame(blocked_window, fg_color="#1a1a1a")
        scroll_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        try:
            # First, get IPs from database
            conn = psycopg2.connect(**self.controller.db_config)
            cursor = conn.cursor()
            
            # Debug: Print current records before displaying
            cursor.execute("SELECT * FROM blocked_ips")
            all_records = cursor.fetchall()
            print("Records found in blocked_ips:", all_records)
            
            cursor.execute("""
                SELECT ip_address, blocked_at, blocked_by 
                FROM blocked_ips 
                ORDER BY blocked_at DESC
            """)
            blocked_ips_db = cursor.fetchall()
            print("Formatted records to display:", blocked_ips_db)
            
            cursor.close()
            conn.close()
            
            # Then, get IPs from iptables
            try:
                iptables_output = subprocess.run(
                    ["sudo", "iptables", "-L", "INPUT", "-n"],
                    capture_output=True,
                    text=True,
                    check=True
                ).stdout
                print("iptables output:", iptables_output)
            except Exception as e:
                print("Error getting iptables:", str(e))
                iptables_output = ""
            
            # Parse iptables output to get blocked IPs
            iptables_ips = set()
            for line in iptables_output.split('\n'):
                if 'DROP' in line and any(char.isdigit() for char in line):
                    parts = line.split()
                    if len(parts) >= 4:
                        ip = parts[3]  # Usually the source IP is in the 4th column
                        if self.validate_ip(ip):
                            iptables_ips.add(ip)
            
            print("IPs found in iptables:", iptables_ips)
            
            # Combine both sources
            db_ips = {ip[0] for ip in blocked_ips_db}
            all_ips = db_ips.union(iptables_ips)
            
            print("All IPs to display:", all_ips)
            
            if not all_ips:
                ctk.CTkLabel(
                    scroll_frame,
                    text="No blocked IPs",
                    font=("Arial", 14),
                    text_color="white"
                ).pack(pady=20)
            else:
                # Show all IPs
                for ip in all_ips:
                    ip_frame = ctk.CTkFrame(scroll_frame, fg_color="#2d2d2d")
                    ip_frame.pack(fill="x", pady=5)
                    
                    info_frame = ctk.CTkFrame(ip_frame, fg_color="transparent")
                    info_frame.pack(side="left", padx=10, pady=5, fill="x", expand=True)
                    
                    ctk.CTkLabel(
                        info_frame,
                        text=f"IP: {ip}",
                        font=("Arial", 14, "bold"),
                        text_color="white"
                    ).pack(anchor="w")
                    
                    # Find matching DB record if exists
                    db_record = next((record for record in blocked_ips_db if record[0] == ip), None)
                    if db_record:
                        ctk.CTkLabel(
                            info_frame,
                            text=f"Blocked by: {db_record[2]} at {db_record[1]}",
                            font=("Arial", 12),
                            text_color="#95a5a6"
                        ).pack(anchor="w")
                    else:
                        ctk.CTkLabel(
                            info_frame,
                            text="Blocked via iptables",
                            font=("Arial", 12),
                            text_color="#95a5a6"
                        ).pack(anchor="w")
                    
                    ctk.CTkButton(
                        ip_frame,
                        text="Unblock",
                        command=lambda ip=ip: self.unblock_ip(ip, blocked_window),
                        fg_color="#e74c3c",
                        hover_color="#c0392b",
                        width=80
                    ).pack(side="right", padx=10)
            
        except Exception as e:
            print(f"Error loading blocked IPs: {e}")
            ctk.CTkLabel(
                scroll_frame,
                text=f"Error loading blocked IPs: {str(e)}",
                text_color="red"
            ).pack(pady=20)

    def save_blocked_ip(self, ip: str):
        """Save blocked IP to database"""
        try:
            conn = psycopg2.connect(**self.controller.db_config)
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO blocked_ips (ip_address, blocked_by) VALUES (%s, %s)",
                (ip, self.controller.username)
            )
            conn.commit()
            cursor.close()
            conn.close()
        except Exception as e:
            print(f"Error saving blocked IP: {e}")

    def unblock_ip(self, ip: str, window=None):
        """Unblock an IP address"""
        try:
            # Remove from iptables
            subprocess.run(
                ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                check=True, capture_output=True
            )
            
            # Remove from database
            conn = psycopg2.connect(**self.controller.db_config)
            cursor = conn.cursor()
            cursor.execute("DELETE FROM blocked_ips WHERE ip_address = %s", (ip,))
            conn.commit()
            cursor.close()
            conn.close()
            
            # Show success message
            messagebox.showinfo("Success", f"Successfully unblocked IP: {ip}")
            
            # Refresh blocked IPs window if open
            if window:
                window.destroy()
                self.show_blocked_ips()
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to unblock IP: {str(e)}")

    def create_test_data(self):
        """Create test data if eve.json doesn't exist or is empty"""
        eve_path = Path("/var/log/suricata/eve.json")
        
        if not eve_path.exists() or eve_path.stat().st_size == 0:
            print("Creating test data...")
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
                    "timestamp": datetime.now().isoformat()
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
                    "timestamp": datetime.now().isoformat()
                }
            ]
            
            with open(eve_path, "w", encoding="utf-8") as f:
                for alert in test_alerts:
                    f.write(json.dumps(alert) + "\n")
                    
            print("Test data created successfully")

    def monitor_logs(self):
        """Monitor logs in real-time"""
        eve_path = Path("/var/log/suricata/eve.json")
        print("🔍 Starting real-time log monitor...")
        
        try:
            with open(eve_path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(0, 2)  # move to end of file
                
                while not self.should_stop:
                    line = f.readline()
                    if not line:
                        time.sleep(0.5)
                        continue
                    try:
                        log_data = json.loads(line)
                        if log_data.get("event_type") == "stats":
                            continue
                        signature = log_data.get("alert", {}).get("signature", f"Event Type: {log_data.get('event_type', 'unknown')}")
                        print(f"🚨 Found event: {signature}")
                        agent_response = process_alert(log_data)
                        self.log_queue.put((log_data, agent_response))
                    except json.JSONDecodeError as e:
                        print(f"⚠️ JSON error: {e}")
        except Exception as e:
            print(f"❌ Log monitoring error: {e}")
    
    def process_log_queue(self):
        """Process logs from the queue"""
        try:
            while True:
                try:
                    log_data, agent_response = self.log_queue.get_nowait()
                    
                    # Safe printing even if no 'alert'
                    signature = log_data.get("alert", {}).get("signature") or log_data.get("event_type", "unknown")
                    print(f"📊 Got from queue: {signature}")
                    
                    self.add_log_to_table(log_data, agent_response)
                except queue.Empty:
                    break
        except Exception as e:
            print(f"❌ Error processing log queue: {e}")
        finally:
            self.after(1000, self.process_log_queue)
    
    def parse_agent_response(self, response: Any) -> tuple:
        """Parse the agent's response to extract action and reason"""
        try:
            response_str = str(response) if response is not None else ""
            response_lower = response_str.lower()
            
            action = "No action"
            reason = "No specific reason provided."
            
            if "block" in response_lower:
                action = "Block IP"
                if "because" in response_lower:
                    reason = response_str.split("because", 1)[1].strip()
                elif "due to" in response_lower:
                    reason = response_str.split("due to", 1)[1].strip()
                else:
                    reason = "Potential threat detected. Blocking as a precaution."
            
            elif "monitor" in response_lower:
                action = "Monitor"
                if "because" in response_lower:
                    reason = response_str.split("because", 1)[1].strip()
                elif "due to" in response_lower:
                    reason = response_str.split("due to", 1)[1].strip()
                else:
                    reason = "Suspicious activity requires further monitoring."
            else:
                if "alert" in response_lower or "suspicious" in response_lower:
                    reason = "Alert analysis suggests potential risk, manual review recommended."
                else:
                    reason = response_str[:200]
            
            return action, reason
            
        except Exception as e:
            print(f"❌ Error parsing agent response: {e}")
            return "Error", str(e)
    
    def add_log_to_table(self, log_data: Dict[str, Any], agent_response: Any):
        """Add a log entry to the table"""
        try:
            event_type = log_data.get("event_type", "unknown")
            src_ip = log_data.get("src_ip", "N/A")
            dest_ip = log_data.get("dest_ip", "N/A")
            timestamp = log_data.get("timestamp", "N/A")
            
            if event_type == "alert":
                alert_data = log_data.get("alert", {})
                threat = alert_data.get("signature", "Unknown Alert")
                severity = alert_data.get("severity", "unknown")
            else:
                threat = f"Event Type: {event_type}"
                severity = "info"
            
            action, reason = self.parse_agent_response(agent_response)
            
            severity_map = {
                "5": "high",
                "4": "medium",
                "3": "medium",
                "2": "low",
                "1": "low"
            }
            severity_str = severity_map.get(str(severity), "low")
            
            # Get current number of items to determine row color
            current_items = len(self.tree.get_children())
            row_tags = (severity_str, 'evenrow' if current_items % 2 == 0 else 'oddrow')
            
            self.tree.insert(
                "", 0,
                values=(
                    f"{threat}",
                    f"{src_ip} → {dest_ip}",
                    severity_str.upper(),
                    timestamp,
                    action,
                    reason
                ),
                tags=row_tags
            )
            
            print(f"✅ Inserted log: {threat} | Severity: {severity_str.upper()} | Action: {action}")
            
            self.logs.insert(0, log_data)
            self.agent_responses.insert(0, agent_response)
            
            if len(self.logs) > 1000:
                self.logs.pop()
                self.agent_responses.pop()
                last_item = self.tree.get_children("")[-1]
                self.tree.delete(last_item)
                
        except Exception as e:
            print(f"❌ Error adding log to table: {e}")
    
    def on_item_double_click(self, event):
        """Handle double click on table item"""
        selection = self.tree.selection()
        if not selection:
            return
        
        item = selection[0]
        idx = self.tree.index(item)
        if idx < len(self.logs):
            log_data = self.logs[idx]
            agent_response = self.agent_responses[idx]
            LogDetailWindow(self, log_data, agent_response)
    
    def search_logs(self):
        """Search logs based on the search term"""
        search_term = self.search_var.get().lower()
        
        # Clear current table
        for item in self.tree.get_children(""):
            self.tree.delete(item)
        
        # Add matching logs
        for i, (log, response) in enumerate(zip(self.logs, self.agent_responses)):
            # Search in various fields
            threat = log.get("alert", {}).get("signature", "").lower()
            action, reason = self.parse_agent_response(response)
            
            if (search_term in threat.lower() or 
                search_term in action.lower() or 
                search_term in reason.lower()):
                self.tree.insert("", "end", values=(
                    log.get("alert", {}).get("signature", "Unknown Threat"),
                    f"{log.get('src_ip', 'N/A')} → {log.get('dest_ip', 'N/A')}",
                    log.get("alert", {}).get("severity", "unknown"),
                    log.get("timestamp", "N/A"),
                    action,
                    reason
                ))
    
    def validate_ip(self, ip: str) -> bool:
        """Validate IP address format"""
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except ValueError:
            return False
    
    def manual_block_ip(self):
        """Manually block an IP address with improved feedback"""
        ip = self.ip_entry.get().strip()
        
        # Reset status
        self.block_status_label.configure(text="")
        
        if not ip:
            self.block_status_label.configure(
                text="⚠️ Please enter an IP address",
                text_color="#f1c40f"  # Warning yellow
            )
            return
        
        if not self.validate_ip(ip):
            self.block_status_label.configure(
                text="❌ Invalid IP address format",
                text_color="#e74c3c"  # Error red
            )
            return
        
        # Create a custom dialog for confirmation
        dialog = ctk.CTkInputDialog(
            title="Confirm IP Block",
            text=f"🚫 Are you sure you want to block {ip}?\n\nThis will prevent all incoming traffic from this IP address."
        )
        
        if dialog.get_input() == "":  # User clicked OK
            try:
                # Show blocking in progress
                self.block_status_label.configure(
                    text="⏳ Blocking IP...",
                    text_color="#3498db"  # Info blue
                )
                self.block_button.configure(state="disabled")
                self.update()
                
                # Execute the blocking command with sudo
                subprocess.run(
                    ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                    check=True, capture_output=True
                )
                
                # Save to database
                try:
                    conn = psycopg2.connect(**self.controller.db_config)
                    cursor = conn.cursor()
                    
                    # Debug: Print the values being inserted
                    print(f"Inserting IP: {ip}, Blocked by: {self.controller.username}")
                    
                    cursor.execute(
                        "INSERT INTO blocked_ips (ip_address, blocked_by) VALUES (%s, %s)",
                        (ip, self.controller.username)
                    )
                    conn.commit()
                    
                    # Debug: Verify the insertion
                    cursor.execute("SELECT * FROM blocked_ips WHERE ip_address = %s", (ip,))
                    print("Newly inserted record:", cursor.fetchone())
                    
                    cursor.close()
                    conn.close()
                    print("Successfully saved IP to database")
                except Exception as db_error:
                    print(f"Database error saving blocked IP: {db_error}")
                    # Even if DB save fails, we show success since the IP was blocked
                
                # Success feedback
                self.block_status_label.configure(
                    text=f"✅ Successfully blocked {ip}",
                    text_color="#2ecc71"  # Success green
                )
                self.ip_entry.delete(0, "end")
                
            except subprocess.CalledProcessError as e:
                self.block_status_label.configure(
                    text=f"❌ Failed to block IP: {e.stderr.decode()}",
                    text_color="#e74c3c"  # Error red
                )
            except Exception as e:
                self.block_status_label.configure(
                    text=f"❌ Error: {str(e)}",
                    text_color="#e74c3c"  # Error red
                )
            finally:
                self.block_button.configure(state="normal")

    def create_table(self):
        """Create the table to display logs"""
        # Create table frame
        self.table_frame = ctk.CTkFrame(self.main_container, fg_color="#131313")
        self.table_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Configure style for Treeview
        style = ttk.Style()
        
        # Use clam theme as base
        style.theme_use('clam')
        
        # Configure the main Treeview style
        style.configure("Treeview", 
                       background="#1a1a1a",
                       fieldbackground="#1a1a1a",
                       foreground="white",
                       rowheight=30,
                       borderwidth=0,
                       font=('Arial', 11))
        
        # Configure the Treeview heading style
        style.configure("Treeview.Heading",
                       background="#1a1a1a",
                       foreground="white",
                       relief="flat",
                       borderwidth=0,
                       font=('Arial', 11, 'bold'))
        
        # Configure selection colors
        style.map('Treeview',
                 background=[('selected', '#333333')],
                 foreground=[('selected', 'white')])
        
        # Configure scrollbar style
        style.configure("Custom.Vertical.TScrollbar",
                       background="#2d2d2d",
                       troughcolor="#1a1a1a",
                       bordercolor="#2d2d2d",
                       arrowcolor="white",
                       relief="flat")
        
        # Create Treeview
        self.tree = ttk.Treeview(self.table_frame,
                                columns=("threat", "ips", "severity", "timestamp", "action", "reason"),
                                show="headings",
                                selectmode="browse",
                                style="Treeview")
        
        # Configure tags for severity colors
        self.tree.tag_configure('high', foreground="#ff3333")
        self.tree.tag_configure('medium', foreground="#ffa500")
        self.tree.tag_configure('low', foreground="white")
        
        # Define columns with specific styling
        headers = {
            "threat": "Threat",
            "ips": "Source → Destination",
            "severity": "Severity",
            "timestamp": "Timestamp",
            "action": "AI Action",
            "reason": "Reason"
        }
        
        for col, text in headers.items():
            self.tree.heading(col, text=text)
            self.tree.column(col, anchor="w")  # Left-align all columns
        
        # Configure column widths
        self.tree.column("threat", width=300, minwidth=200, stretch=True)
        self.tree.column("ips", width=250, minwidth=150, stretch=True)
        self.tree.column("severity", width=100, minwidth=80, stretch=True)
        self.tree.column("timestamp", width=180, minwidth=120, stretch=True)
        self.tree.column("action", width=150, minwidth=100, stretch=True)
        self.tree.column("reason", width=400, minwidth=200, stretch=True)
        
        # Add vertical scrollbar with custom style
        self.vsb = ttk.Scrollbar(self.table_frame, orient="vertical", 
                                command=self.tree.yview,
                                style="Custom.Vertical.TScrollbar")
        self.tree.configure(yscrollcommand=self.vsb.set)
        
        # Grid layout
        self.tree.grid(row=0, column=0, sticky="nsew")
        self.vsb.grid(row=0, column=1, sticky="ns")
        
        # Configure grid weights
        self.table_frame.grid_rowconfigure(0, weight=1)
        self.table_frame.grid_columnconfigure(0, weight=1)
        
        # Bind click event
        self.tree.bind("<Double-1>", self.on_item_double_click)
        
        # Store logs and responses
        self.logs = []
        self.agent_responses = []

class DashboardFrame(ctk.CTkFrame):
    def __init__(self, parent, controller):
        super().__init__(parent, fg_color="#131313")
        self.controller = controller
        
        # Create a frame to hold the dashboard
        self.dashboard_container = ctk.CTkFrame(self, fg_color="#131313")
        self.dashboard_container.pack(fill="both", expand=True)
        
        # Start the dashboard server in a separate thread
        self.server_thread = threading.Thread(target=self.start_dashboard, daemon=True)
        self.server_thread.start()
        
        # Create a label with instructions
        self.dashboard_label = ctk.CTkLabel(
            self.dashboard_container,
            text="Dashboard is running at: http://127.0.0.1:8051\nClick below to open in your browser",
            font=("Arial", 14),
            text_color="white"
        )
        self.dashboard_label.pack(pady=20)
        
        # Add a button to open in browser
        self.open_button = ctk.CTkButton(
            self.dashboard_container,
            text="Open Dashboard",
            command=self.open_in_browser,
            font=("Arial", 14),
            fg_color="#0BA0E3",
            hover_color="#098fc7"
        )
        self.open_button.pack(pady=10)
    
    def start_dashboard(self):
        from dashboard import app
        app.run(debug=False, port=8051)
    
    def open_in_browser(self):
        import webbrowser
        webbrowser.open("http://127.0.0.1:8051")

class LogDetailWindow(ctk.CTkToplevel):
    def __init__(self, parent, log_data: Dict[str, Any], agent_response: str):
        super().__init__(parent)
        self.title("Log Details")
        self.geometry("1920x1080")
        
        # Store data
        self.log_data = log_data
        self.agent_response = agent_response
        
        # Create main frame with scrollable content
        self.main_frame = ctk.CTkScrollableFrame(self)
        self.main_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # IP Information Section
        self.ip_frame = ctk.CTkFrame(self.main_frame)
        self.ip_frame.pack(fill="x", padx=10, pady=5)
        
        # Source IP with Block and Unblock buttons
        self.src_ip_frame = ctk.CTkFrame(self.ip_frame)
        self.src_ip_frame.pack(fill="x", pady=5)
        ctk.CTkLabel(self.src_ip_frame, text="Source IP:", font=("Arial", 12, "bold")).pack(side="left", padx=5)
        src_ip = self.log_data.get("src_ip", "N/A")
        ctk.CTkLabel(self.src_ip_frame, text=src_ip).pack(side="left", padx=5)
        ctk.CTkButton(self.src_ip_frame, text="Block IP", 
                     command=lambda: self.block_ip(src_ip),
                     width=100).pack(side="right", padx=5)
        ctk.CTkButton(self.src_ip_frame, text="Unblock IP", 
                     command=lambda: self.unblock_ip(src_ip),
                     width=100).pack(side="right", padx=5)
        
        # Destination IP
        self.dst_ip_frame = ctk.CTkFrame(self.ip_frame)
        self.dst_ip_frame.pack(fill="x", pady=5)
        ctk.CTkLabel(self.dst_ip_frame, text="Destination IP:", font=("Arial", 12, "bold")).pack(side="left", padx=5)
        ctk.CTkLabel(self.dst_ip_frame, text=self.log_data.get("dest_ip", "N/A")).pack(side="left", padx=5)
        
        # Protocol
        self.proto_frame = ctk.CTkFrame(self.ip_frame)
        self.proto_frame.pack(fill="x", pady=5)
        ctk.CTkLabel(self.proto_frame, text="Protocol:", font=("Arial", 12, "bold")).pack(side="left", padx=5)
        ctk.CTkLabel(self.proto_frame, text=self.log_data.get("proto", "N/A")).pack(side="left", padx=5)
        
        # Timestamps
        self.time_frame = ctk.CTkFrame(self.ip_frame)
        self.time_frame.pack(fill="x", pady=5)
        ctk.CTkLabel(self.time_frame, text="Timestamp:", font=("Arial", 12, "bold")).pack(side="left", padx=5)
        ctk.CTkLabel(self.time_frame, text=self.log_data.get("timestamp", "N/A")).pack(side="left", padx=5)
        
        # AI Analysis Section
        self.analysis_frame = ctk.CTkFrame(self.main_frame)
        self.analysis_frame.pack(fill="x", padx=10, pady=5)
        
        ctk.CTkLabel(self.analysis_frame, text="AI Security Analysis", font=("Arial", 14, "bold")).pack(pady=5)
        
        # Only show detailed analysis for medium and high risk alerts
        severity = self.log_data.get("alert", {}).get("severity", 0)
        if isinstance(severity, str):
            try:
                severity = int(severity)
            except ValueError:
                severity = 0
                
        if severity >= 3:  # Medium or High risk
            analysis_text = (
                "🔍 Threat Analysis Summary:\n\n"
                "1. Alert Classification:\n"
                f"   • Signature: {self.log_data.get('alert', {}).get('signature', 'Unknown')}\n"
                f"   • Risk Level: {'Low' if severity <= 2 else 'Medium' if severity == 3 else 'High (MUST BLOCK)'} (Severity: {severity})\n\n"
                "2. Technical Details:\n"
                f"   • Protocol: {self.log_data.get('proto', 'Unknown')}\n"
                f"   • Source IP: {self.log_data.get('src_ip', 'Unknown')}\n"
                f"   • Destination IP: {self.log_data.get('dest_ip', 'Unknown')}\n\n"
                
                "3. Response Status:\n"
                f"   {self.agent_response}"
            )
        else:  # Low risk
            analysis_text = self.agent_response
            
        self.analysis_text = ctk.CTkTextbox(self.analysis_frame, height=300)
        self.analysis_text.pack(fill="x", padx=5, pady=5)
        self.analysis_text.insert("1.0", analysis_text)
        self.analysis_text.configure(state="disabled")
        
        # View Log Button
        self.view_log_btn = ctk.CTkButton(self.main_frame, text="View Full Log", 
                                         command=self.show_full_log)
        self.view_log_btn.pack(pady=10)
        
        # Full Log Text Area (hidden by default)
        self.log_text = ctk.CTkTextbox(self.main_frame, height=200)
        self.log_text.insert("1.0", json.dumps(self.log_data, indent=2))
        self.log_text.configure(state="disabled")
        self.log_text.pack_forget()
        
    def show_full_log(self):
        """Toggle the visibility of the full log text area"""
        if self.log_text.winfo_ismapped():
            self.log_text.pack_forget()
            self.view_log_btn.configure(text="View Full Log")
        else:
            self.log_text.pack(fill="both", expand=True, padx=10, pady=10)
            self.view_log_btn.configure(text="Hide Full Log")
            
    def _run_with_privileges(self, command):
        """Run a command with elevated privileges using pkexec or sudo"""
        try:
            # First try with pkexec (preferred)
            result = subprocess.run(["pkexec"] + command,
                                  check=True, capture_output=True)
            return result
        except FileNotFoundError:
            # If pkexec is not available, try with sudo
            try:
                result = subprocess.run(["sudo", "-A"] + command,
                                      check=True, capture_output=True,
                                      env={**os.environ, 'SUDO_ASKPASS': '/usr/lib/ssh/ssh-askpass'})
                return result
            except FileNotFoundError:
                # If neither is available, try with regular sudo
                return subprocess.run(["sudo"] + command,
                                    check=True, capture_output=True)

    def block_ip(self, ip: str):
        """Block an IP address using iptables"""
        if messagebox.askyesno("Confirm Block", f"Are you sure you want to block {ip}?"):
            try:
                self._run_with_privileges(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
                messagebox.showinfo("Success", f"Successfully blocked IP: {ip}")
            except subprocess.CalledProcessError as e:
                messagebox.showerror("Error", f"Failed to block IP. Root privileges required.\nError: {e.stderr.decode()}")
            except Exception as e:
                messagebox.showerror("Error", f"An error occurred: {str(e)}")

    def unblock_ip(self, ip: str):
        """Unblock an IP address using iptables"""
        if messagebox.askyesno("Confirm Unblock", f"Are you sure you want to unblock {ip}?"):
            try:
                self._run_with_privileges(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
                messagebox.showinfo("Success", f"Successfully unblocked IP: {ip}")
            except subprocess.CalledProcessError as e:
                messagebox.showerror("Error", f"Failed to unblock IP. Root privileges required.\nError: {e.stderr.decode()}")
            except Exception as e:
                messagebox.showerror("Error", f"An error occurred: {str(e)}")

class SettingsFrame(ctk.CTkFrame):
    def __init__(self, parent, controller):
        super().__init__(parent, fg_color="#131313")
        self.controller = controller
        
        # Constants
        self.CONTENT_COLOR = "#131313"
        self.ENTRY_BG = "#232329"
        self.BTN_BLUE = "#17a9ff"
        self.ENTRY_HEIGHT = 40
        
        # Create main container with scrollable frame
        main_container = ctk.CTkScrollableFrame(self, fg_color=self.CONTENT_COLOR)
        main_container.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Account Info Section
        self.create_account_info(main_container)
        
        # Separator
        separator1 = ctk.CTkFrame(main_container, fg_color="#2E2E2E", height=2)
        separator1.pack(fill="x", pady=30)
        
        # Password Change Section
        self.create_password_section(main_container)
        
        # Separator
        separator2 = ctk.CTkFrame(main_container, fg_color="#2E2E2E", height=2)
        separator2.pack(fill="x", pady=30)
        
        # Support Section
        self.create_support_section(main_container)
        
        # Separator
        separator3 = ctk.CTkFrame(main_container, fg_color="#2E2E2E", height=2)
        separator3.pack(fill="x", pady=30)
        
        # Privacy Policy Section
        self.create_privacy_section(main_container)
    
    def create_support_section(self, parent):
        # Support Title
        title_label = ctk.CTkLabel(
            parent,
            text="Support",
            font=("Arial", 24, "bold"),
            text_color="white"
        )
        title_label.pack(anchor="w", pady=(0, 20))
        
        # Support frame
        support_frame = ctk.CTkFrame(
            parent,
            fg_color=self.ENTRY_BG,
            corner_radius=10
        )
        support_frame.pack(fill="x")
        
        # Support content
        content_frame = ctk.CTkFrame(support_frame, fg_color="transparent")
        content_frame.pack(fill="x", padx=20, pady=20)
        
        # Contact information
        ctk.CTkLabel(
            content_frame,
            text="Need help? Contact our support team:",
            font=("Arial", 16, "bold"),
            text_color="white"
        ).pack(anchor="w", pady=(0, 10))
        
        # Email
        email_frame = ctk.CTkFrame(content_frame, fg_color="transparent")
        email_frame.pack(fill="x", pady=5)
        
        ctk.CTkLabel(
            email_frame,
            text="📧 Email:",
            font=("Arial", 14, "bold"),
            text_color="#808080"
        ).pack(side="left")
        
        ctk.CTkLabel(
            email_frame,
            text="watchtowersupp@gmail.com",
            font=("Arial", 14),
            text_color=self.BTN_BLUE,
            cursor="hand2"
        ).pack(side="left", padx=10)
        
        # Phone
        phone_frame = ctk.CTkFrame(content_frame, fg_color="transparent")
        phone_frame.pack(fill="x", pady=5)
        
        ctk.CTkLabel(
            phone_frame,
            text="📞 Phone:",
            font=("Arial", 14, "bold"),
            text_color="#808080"
        ).pack(side="left")
        
        ctk.CTkLabel(
            phone_frame,
            text="+1 (555) 123-4567",
            font=("Arial", 14),
            text_color="white"
        ).pack(side="left", padx=10)
        
        # Hours
        hours_frame = ctk.CTkFrame(content_frame, fg_color="transparent")
        hours_frame.pack(fill="x", pady=5)
        
        ctk.CTkLabel(
            hours_frame,
            text="🕒 Hours:",
            font=("Arial", 14, "bold"),
            text_color="#808080"
        ).pack(side="left")
        
        ctk.CTkLabel(
            hours_frame,
            text="24/7 Support",
            font=("Arial", 14),
            text_color="white"
        ).pack(side="left", padx=10)

        # Website
        website_frame = ctk.CTkFrame(content_frame, fg_color="transparent")
        website_frame.pack(fill="x", pady=5)
        
        ctk.CTkLabel(
            website_frame,
            text="🌐 Website:",
            font=("Arial", 14, "bold"),
            text_color="#808080"
        ).pack(side="left")
        
        website_link = ctk.CTkLabel(
            website_frame,
            text="watchtower.digital",
            font=("Arial", 14),
            text_color=self.BTN_BLUE,
            cursor="hand2"
        )
        website_link.pack(side="left", padx=10)
        website_link.bind("<Button-1>", lambda e: webbrowser.open("https://watchtower.digital"))
    
    def create_privacy_section(self, parent):
        # Privacy Policy Title
        title_label = ctk.CTkLabel(
            parent,
            text="Privacy Policy",
            font=("Arial", 24, "bold"),
            text_color="white"
        )
        title_label.pack(anchor="w", pady=(0, 20))
        
        # Privacy frame
        privacy_frame = ctk.CTkFrame(
            parent,
            fg_color=self.ENTRY_BG,
            corner_radius=10
        )
        privacy_frame.pack(fill="x")
        
        # Privacy content
        content_frame = ctk.CTkFrame(privacy_frame, fg_color="transparent")
        content_frame.pack(fill="x", padx=20, pady=20)
        
        privacy_text = """
WatchTower Privacy Policy

1. Data Collection
We collect and process the following information:
• System logs and alerts
• User authentication data
• IP addresses and network traffic data
• Chat messages and communication data

2. Data Usage
Your data is used to:
• Provide security monitoring services
• Detect and prevent security threats
• Improve our services
• Maintain communication records

3. Data Protection
We implement industry-standard security measures to protect your data:
• End-to-end encryption for communications
• Secure data storage
• Regular security audits
• Access controls and authentication

4. Data Retention
• System logs are retained for 30 days
• Chat messages are stored until manually deleted
• User account data is retained while account is active

5. Your Rights
You have the right to:
• Access your personal data
• Request data deletion
• Opt out of non-essential data collection
• Receive a copy of your data

For more information, contact our privacy team at watchtowersupp@gmail.com
"""
        
        # Create text widget for privacy policy
        text_widget = ctk.CTkTextbox(
            content_frame,
            font=("Arial", 14),
            text_color="white",
            fg_color="transparent",
            height=400,
            wrap="word"
        )
        text_widget.pack(fill="both", expand=True)
        text_widget.insert("1.0", privacy_text)
        text_widget.configure(state="disabled")  # Make read-only
        
        # Add contact button
        contact_btn = ctk.CTkButton(
            content_frame,
            text="Contact Privacy Team",
            font=("Arial", 14, "bold"),
            height=self.ENTRY_HEIGHT,
            fg_color=self.BTN_BLUE,
            command=lambda: self.open_email("privacy@watchtower.com")
        )
        contact_btn.pack(pady=(20, 0))
    
    def open_email(self, email):
        webbrowser.open(f"mailto:{email}")
        
    def create_account_info(self, parent):
        # Account Info Title
        title_label = ctk.CTkLabel(
            parent,
            text="Account Information",
            font=("Arial", 24, "bold"),
            text_color="white"
        )
        title_label.pack(anchor="w", pady=(0, 20))
        
        # Account info frame
        account_frame = ctk.CTkFrame(
            parent,
            fg_color=self.ENTRY_BG,
            corner_radius=10
        )
        account_frame.pack(fill="x")
        
        try:
            # Connect to database
            conn = psycopg2.connect(**self.controller.db_config)
            cursor = conn.cursor(cursor_factory=RealDictCursor)
            
            # Get user data
            cursor.execute("""
                SELECT username, firstname, lastname, email, userrole
                FROM login
                WHERE username = %s
            """, (self.controller.username,))
            
            user_data = cursor.fetchone()
            cursor.close()
            conn.close()
            
            if user_data:
                # Create fields with user data
                fields = [
                    ("Username", user_data["username"]),
                    ("First Name", user_data["firstname"]),
                    ("Last Name", user_data["lastname"]),
                    ("Email", user_data["email"]),
                    ("Role", user_data["userrole"])
                ]
                
                for i, (label, value) in enumerate(fields):
                    field_frame = ctk.CTkFrame(account_frame, fg_color="transparent")
                    field_frame.pack(fill="x", padx=20, pady=10)
                    
                    ctk.CTkLabel(
                        field_frame,
                        text=label,
                        font=("Arial", 14, "bold"),
                        text_color="#808080"
                    ).pack(anchor="w")
                    
                    ctk.CTkLabel(
                        field_frame,
                        text=value,
                        font=("Arial", 16),
                        text_color="white"
                    ).pack(anchor="w", pady=(5, 0))
                    
                    if i < len(fields) - 1:
                        ctk.CTkFrame(
                            account_frame,
                            fg_color="#2E2E2E",
                            height=1
                        ).pack(fill="x", padx=20)
            
        except Exception as e:
            error_label = ctk.CTkLabel(
                account_frame,
                text=f"Error loading user data: {str(e)}",
                text_color="red",
                font=("Arial", 14)
            )
            error_label.pack(pady=20)
    
    def create_password_section(self, parent):
        # Password Change Title
        title_label = ctk.CTkLabel(
            parent,
            text="Change Password",
            font=("Arial", 24, "bold"),
            text_color="white"
        )
        title_label.pack(anchor="w", pady=(0, 20))
        
        # Password change frame
        password_frame = ctk.CTkFrame(
            parent,
            fg_color=self.ENTRY_BG,
            corner_radius=10
        )
        password_frame.pack(fill="x")
        
        # Current Password
        current_pw_frame = ctk.CTkFrame(password_frame, fg_color="transparent")
        current_pw_frame.pack(fill="x", padx=20, pady=10)
        
        ctk.CTkLabel(
            current_pw_frame,
            text="Current Password",
            font=("Arial", 14, "bold"),
            text_color="#808080"
        ).pack(anchor="w")
        
        self.current_pw = ctk.CTkEntry(
            current_pw_frame,
            placeholder_text="Enter current password",
            font=("Arial", 14),
            show="•",
            height=self.ENTRY_HEIGHT
        )
        self.current_pw.pack(fill="x", pady=(5, 0))
        
        # New Password
        new_pw_frame = ctk.CTkFrame(password_frame, fg_color="transparent")
        new_pw_frame.pack(fill="x", padx=20, pady=10)
        
        ctk.CTkLabel(
            new_pw_frame,
            text="New Password",
            font=("Arial", 14, "bold"),
            text_color="#808080"
        ).pack(anchor="w")
        
        self.new_pw = ctk.CTkEntry(
            new_pw_frame,
            placeholder_text="Enter new password",
            font=("Arial", 14),
            show="•",
            height=self.ENTRY_HEIGHT
        )
        self.new_pw.pack(fill="x", pady=(5, 0))
        
        # Confirm Password
        confirm_pw_frame = ctk.CTkFrame(password_frame, fg_color="transparent")
        confirm_pw_frame.pack(fill="x", padx=20, pady=10)
        
        ctk.CTkLabel(
            confirm_pw_frame,
            text="Confirm New Password",
            font=("Arial", 14, "bold"),
            text_color="#808080"
        ).pack(anchor="w")
        
        self.confirm_pw = ctk.CTkEntry(
            confirm_pw_frame,
            placeholder_text="Confirm new password",
            font=("Arial", 14),
            show="•",
            height=self.ENTRY_HEIGHT
        )
        self.confirm_pw.pack(fill="x", pady=(5, 0))
        
        # Error/Success message label
        self.message_label = ctk.CTkLabel(
            password_frame,
            text="",
            font=("Arial", 14),
            text_color="red"
        )
        self.message_label.pack(pady=(10, 0))
        
        # Update Password Button
        update_btn = ctk.CTkButton(
            password_frame,
            text="Update Password",
            font=("Arial", 14, "bold"),
            height=self.ENTRY_HEIGHT,
            fg_color=self.BTN_BLUE,
            command=self.update_password
        )
        update_btn.pack(pady=20)
    
    def update_password(self):
        current = self.current_pw.get()
        new = self.new_pw.get()
        confirm = self.confirm_pw.get()
        
        # Reset message
        self.message_label.configure(text="")
        
        # Validate input
        if not all([current, new, confirm]):
            self.message_label.configure(text="All fields are required")
            return
        
        if new != confirm:
            self.message_label.configure(text="New passwords do not match")
            return
        
        if len(new) < 8:
            self.message_label.configure(text="Password must be at least 8 characters")
            return
        
        try:
            # Connect to database
            conn = psycopg2.connect(**self.controller.db_config)
            cursor = conn.cursor()
            
            # Verify current password
            cursor.execute(
                "SELECT password_hash FROM login WHERE username = %s",
                (self.controller.username,)
            )
            result = cursor.fetchone()
            
            if not result or result[0] != hashlib.sha256(current.encode()).hexdigest():
                self.message_label.configure(text="Current password is incorrect")
                return
            
            # Update password
            cursor.execute(
                "UPDATE login SET password_hash = %s WHERE username = %s",
                (hashlib.sha256(new.encode()).hexdigest(), self.controller.username)
            )
            conn.commit()
            
            # Clear fields and show success
            self.current_pw.delete(0, 'end')
            self.new_pw.delete(0, 'end')
            self.confirm_pw.delete(0, 'end')
            self.message_label.configure(text="Password updated successfully", text_color="green")
            
        except Exception as e:
            self.message_label.configure(text=f"Error updating password: {str(e)}")
        finally:
            if 'conn' in locals():
                conn.close()

class UserManagementFrame(ctk.CTkFrame):
    def __init__(self, parent, controller):
        super().__init__(parent, fg_color="#131313")
        self.controller = controller
        
        # Constants
        self.COLORS = {
            "bg": "#222222",
            "secondary": "#444444",
            "hover": "#333333",
            "text": "white",
            "accent": "#2a2a2a"
        }
        
        self.TABLE_COLORS = {
            "bg": "#1e1e1e",        # Background color
            "fg": "#f4feff",        # Text color
            "header_bg": "#1f1f1f", # Header background
            "header_fg": "#FFFFFF", # Header text
            "border": "#0ba0e3",    # Border color
            "select_bg": "#F0F0F0"  # Selection highlight
        }
        
        # Column headers for user table
        self.COLUMNS = ("Email", "Username", "First Name", "Last Name", "Role")
        
        # Initialize state
        self.all_users = self.load_users_from_db()
        self.displayed_users = list(self.all_users)
        self.selected_users = set()
        
        # Create UI
        self.create_ui()
    
    def create_ui(self):
        # Create main container
        self.main_frame = ctk.CTkFrame(self, fg_color=self.COLORS["bg"])
        self.main_frame.pack(fill="both", expand=True)
        
        # Create frames
        self.create_main_frame()
        self.create_add_user_frame()
        
        # Show main screen initially
        self.show_main_screen()
    
    def create_main_frame(self):
        # Top navigation bar
        top_frame = ctk.CTkFrame(self.main_frame, fg_color=self.COLORS["bg"])
        top_frame.pack(fill="x", padx=20, pady=(20, 10))
        
        # Title
        ctk.CTkLabel(
            top_frame, 
            text="Manage Users", 
            font=("Arial", 18), 
            text_color=self.COLORS["text"]
        ).pack(side="left", padx=(10, 0))
        
        # Search bar
        search_frame = ctk.CTkFrame(
            top_frame, 
            fg_color=self.COLORS["secondary"], 
            corner_radius=8
        )
        search_frame.pack(side="right", padx=(0, 10))
        
        search_img = ctk.CTkImage(Image.open("/home/zalma/Downloads/watchtower/watchtower/icons/search.png"), size=(20, 20))
        ctk.CTkLabel(search_frame, image=search_img, text="").pack(
            side="left", padx=5, pady=4)
        
        self.search_entry = ctk.CTkEntry(
            search_frame,
            placeholder_text="Search…",
            width=300,
            height=27,
            fg_color=self.COLORS["secondary"],
            border_width=0,
            placeholder_text_color="lightgray",
            text_color=self.COLORS["text"]
        )
        self.search_entry.pack(side="left", padx=(0, 5), pady=4)
        
        # User table container
        container = tk.Frame(self.main_frame, bg=self.COLORS["bg"])
        container.pack(fill="both", expand=True, padx=20, pady=(10, 10))
        
        self.canvas = tk.Canvas(
            container, 
            highlightthickness=0, 
            bg=self.COLORS["bg"]
        )
        
        v_scroll = ttk.Scrollbar(
            container,
            orient="vertical",
            command=self.canvas.yview,
            style="Custom.Vertical.TScrollbar"
        )
        self.canvas.configure(yscrollcommand=v_scroll.set)
        
        v_scroll.pack(side="right", fill="y")
        self.canvas.pack(side="left", fill="both", expand=True)
        
        self.inner_frame = tk.Frame(self.canvas, bg="white")
        self.inner_window = self.canvas.create_window(
            (0, 0), 
            window=self.inner_frame, 
            anchor="nw"
        )
        
        self.inner_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        )
        self.canvas.bind(
            "<Configure>",
            lambda e: self.canvas.itemconfigure(self.inner_window, width=e.width)
        )
        
        for c in range(len(self.COLUMNS) + 1):
            self.inner_frame.grid_columnconfigure(c, weight=1)
        
        # Bottom buttons
        bottom_frame = ctk.CTkFrame(
            self.main_frame, 
            fg_color=self.COLORS["bg"]
        )
        bottom_frame.pack(fill="x", padx=20, pady=(0, 20))
        
        # Delete button (initially disabled)
        self.delete_btn = ctk.CTkButton(
            bottom_frame,
            text="Delete User",
            width=120,
            fg_color="red",
            hover_color="#b22222",
            text_color="white",
            state="disabled",
            command=self.delete_selected
        )
        self.delete_btn.pack(side="right", padx=(25, 10))
        
        # Add user button
        ctk.CTkButton(
            bottom_frame,
            text="Add User",
            width=120,
            command=self.show_add_screen
        ).pack(side="right")
        
        # Bind search functionality
        self.search_entry.bind("<KeyRelease>", self.handle_search)
        
        # Setup styles
        self.setup_styles()
    
    def create_add_user_frame(self):
        self.add_ui_frame = ctk.CTkFrame(
            self, 
            fg_color=self.COLORS["bg"]
        )
        
        # Header
        header_row = ctk.CTkFrame(
            self.add_ui_frame, 
            fg_color="transparent"
        )
        header_row.pack(anchor="nw", padx=20, pady=(20, 0), fill="x")
        
        back_img = ctk.CTkImage(Image.open("/home/zalma/Downloads/watchtower/watchtower/icons/back.png"), size=(24, 24))
        ctk.CTkButton(
            header_row,
            image=back_img,
            text="",
            fg_color="transparent",
            hover_color=self.COLORS["hover"],
            width=30,
            height=30,
            command=self.show_main_screen
        ).pack(side="left")
        
        ctk.CTkLabel(
            header_row,
            text=" Add New User",
            font=("Arial", 18),
            text_color=self.COLORS["text"]
        ).pack(side="left", padx=(10, 0))
        
        # Form container
        center_frame = ctk.CTkFrame(
            self.add_ui_frame,
            fg_color=self.COLORS["secondary"],
            corner_radius=10
        )
        center_frame.pack(padx=80, pady=(20, 40), fill="x")
        
        # Form fields
        self.first_entry = ctk.CTkEntry(
            center_frame,
            placeholder_text="First Name"
        )
        self.first_entry.pack(fill="x", padx=20, pady=(36, 24))
        
        self.last_entry = ctk.CTkEntry(
            center_frame,
            placeholder_text="Last Name"
        )
        self.last_entry.pack(fill="x", padx=20, pady=(0, 24))
        
        self.email_entry = ctk.CTkEntry(
            center_frame,
            placeholder_text="Email"
        )
        self.email_entry.pack(fill="x", padx=20, pady=(0, 24))
        
        self.user_entry = ctk.CTkEntry(
            center_frame,
            placeholder_text="Username"
        )
        self.user_entry.pack(fill="x", padx=20, pady=(0, 24))
        
        self.pass_entry = ctk.CTkEntry(
            center_frame,
            placeholder_text="Password",
            show="*"
        )
        self.pass_entry.pack(fill="x", padx=20, pady=(0, 24))
        
        # Role selector
        self.role_cb = ctk.CTkComboBox(
            center_frame,
            values=["Admin", "User"]
        )
        self.role_cb.set("Select Role")
        self.role_cb.pack(fill="x", padx=20, pady=(0, 32))
        
        # Save button (initially disabled)
        self.save_btn = ctk.CTkButton(
            center_frame,
            text="Save",
            width=120,
            command=self.save_user,
            state="disabled"
        )
        self.save_btn.pack(pady=(40, 20))
        
        # Bind validation to form fields
        for widget in (
            self.first_entry, 
            self.last_entry, 
            self.email_entry, 
            self.user_entry, 
            self.pass_entry
        ):
            widget.bind("<KeyRelease>", lambda e: self.validate_form())
        
        self.role_cb.configure(command=lambda _: self.validate_form())
    
    def setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure(
            "Custom.Vertical.TScrollbar",
            gripcount=0,
            background=self.COLORS["bg"],
            troughcolor=self.COLORS["bg"],
            bordercolor=self.COLORS["bg"],
            lightcolor=self.COLORS["bg"],
            darkcolor=self.COLORS["bg"],
            arrowcolor="#BBBBBB"
        )
        style.map(
            "Custom.Vertical.TScrollbar",
            background=[('active', self.COLORS["accent"]), ('!active', self.COLORS["bg"])],
            arrowcolor=[('active', '#BBBBBB'), ('!active', '#BBBBBB')]
        )
    
    def build_rows(self):
        # Clear existing widgets
        for widget in self.inner_frame.winfo_children():
            widget.destroy()

        # Header row
        tk.Label(
            self.inner_frame,
            text="",
            bg=self.TABLE_COLORS["header_bg"],
            fg=self.TABLE_COLORS["header_fg"],
            bd=1,
            relief="solid",
            padx=22,
            pady=12,
            highlightbackground=self.TABLE_COLORS["border"],
            highlightthickness=1
        ).grid(row=0, column=0, sticky="nsew")
        
        for idx, name in enumerate(self.COLUMNS, start=1):
            tk.Label(
                self.inner_frame,
                text=name,
                font=("Arial", 12, "bold"),
                bg=self.TABLE_COLORS["header_bg"],
                fg=self.TABLE_COLORS["header_fg"],
                bd=1,
                relief="solid",
                padx=22,
                pady=12,
                highlightbackground=self.TABLE_COLORS["border"],
                highlightthickness=1
            ).grid(row=0, column=idx, sticky="nsew")

        # Data rows
        self.checkbox_vars = []
        for r_idx, user in enumerate(self.displayed_users, start=1):
            var = tk.BooleanVar(value=(user[1] in self.selected_users))
            
            # Enhanced checkbox styling
            cb = tk.Checkbutton(
                self.inner_frame,
                variable=var,
                bg=self.TABLE_COLORS["bg"],
                activebackground=self.TABLE_COLORS["bg"],
                selectcolor="#444444",  # Gray background for checkbox
                fg=self.TABLE_COLORS["border"],  # Light blue color for checkmark
                bd=1,
                relief="solid",
                highlightbackground=self.TABLE_COLORS["border"],
                highlightcolor=self.TABLE_COLORS["border"],
                highlightthickness=1,
                padx=16,
                pady=10,
                command=lambda i=r_idx-1: self.on_check(i)
            )
            cb.grid(row=r_idx, column=0, sticky="nsew")
            self.checkbox_vars.append((var, user[1]))
            
            # Data cells
            for c_idx, val in enumerate(user, start=1):
                tk.Label(
                    self.inner_frame,
                    text=val,
                    bg=self.TABLE_COLORS["bg"],
                    fg=self.TABLE_COLORS["fg"],
                    bd=1,
                    relief="solid",
                    padx=22,
                    pady=12,
                    highlightbackground=self.TABLE_COLORS["border"],
                    highlightthickness=1
                ).grid(row=r_idx, column=c_idx, sticky="nsew")

        self.update_delete_button_state()
    
    def show_main_screen(self):
        self.add_ui_frame.pack_forget()
        self.main_frame.pack(fill="both", expand=True)
        self.refresh_data()
    
    def show_add_screen(self):
        self.main_frame.pack_forget()
        self.add_ui_frame.pack(fill="both", expand=True)
        self.clear_form()
    
    def load_users_from_db(self):
        try:
            conn = psycopg2.connect(**self.controller.db_config)
            cur = conn.cursor()
            cur.execute("""
                SELECT email, username, firstname, lastname, userrole
                FROM login
                ORDER BY id
            """)
            users = cur.fetchall()
            cur.close()
            conn.close()
            return users
        except Exception as e:
            print(f"Database error: {e}")
            return []
    
    def on_check(self, index):
        var, uname = self.checkbox_vars[index]
        if var.get():
            self.selected_users.add(uname)
        else:
            self.selected_users.discard(uname)
        self.build_rows()
    
    def update_delete_button_state(self):
        self.delete_btn.configure(
            state="normal" if self.selected_users else "disabled"
        )
    
    def refresh_data(self):
        self.all_users = self.load_users_from_db()
        self.displayed_users = list(self.all_users)
        self.build_rows()
    
    def delete_selected(self):
        try:
            conn = psycopg2.connect(**self.controller.db_config)
            cursor = conn.cursor()
            for uname in list(self.selected_users):
                cursor.execute(
                    "DELETE FROM login WHERE username = %s", 
                    (uname,)
                )
            conn.commit()
            cursor.close()
            conn.close()
            
            self.selected_users.clear()
            self.refresh_data()
        except Exception as e:
            print(f"Error deleting users: {e}")
    
    def clear_form(self):
        self.first_entry.delete(0, tk.END)
        self.last_entry.delete(0, tk.END)
        self.email_entry.delete(0, tk.END)
        self.user_entry.delete(0, tk.END)
        self.pass_entry.delete(0, tk.END)
        self.role_cb.set("Select Role")
        self.validate_form()
    
    def validate_form(self):
        filled = all([
            self.first_entry.get().strip(),
            self.last_entry.get().strip(),
            self.email_entry.get().strip(),
            self.user_entry.get().strip(),
            self.pass_entry.get().strip(),
            self.role_cb.get() in ("Admin", "User")
        ])
        self.save_btn.configure(state="normal" if filled else "disabled")
    
    def save_user(self):
        try:
            conn = psycopg2.connect(**self.controller.db_config)
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO login (
                    email, username, password_hash, 
                    firstname, lastname, userrole
                ) VALUES (%s, %s, %s, %s, %s, %s)
            """, (
                self.email_entry.get(),
                self.user_entry.get(),
                hashlib.sha256(self.pass_entry.get().encode()).hexdigest(),
                self.first_entry.get(),
                self.last_entry.get(),
                self.role_cb.get()
            ))
            conn.commit()
            cursor.close()
            conn.close()
            
            self.show_main_screen()
        except Exception as e:
            print(f"Error saving user: {e}")
    
    def handle_search(self, event):
        search_term = self.search_entry.get().lower()
        self.displayed_users = [
            u for u in self.all_users
            if search_term in str(u).lower()
        ]
        self.build_rows()

class MainFrame(ctk.CTkFrame):
    def __init__(self, parent, controller):
        super().__init__(parent, fg_color="#131313")
        self.controller = controller
        
        # Constants
        self.icon_size = 35  # slightly smaller icons
        self.sidebar_width = int(self.icon_size * 3.5)  # more breathing space in sidebar
        self.underline_thickness = 2
        self.underline_padding_x = 6
        self.button_spacing = 21
        
        # Create main container
        self.container = ctk.CTkFrame(self, fg_color="#131313")
        self.container.pack(fill="both", expand=True)
        
        # Create sidebar
        self.create_sidebar()
        
        # Create main content area
        self.main_content = ctk.CTkFrame(self.container, fg_color="#131313")
        self.main_content.pack(side="right", fill="both", expand=True)
        
        # Initialize frames dictionary
        self.frames = {}
        
        # Create frames
        self.frames["home"] = HomeFrame(self.main_content, self.controller)
        self.frames["chat"] = ChatFrame(self.main_content, self.controller)
        self.frames["monitor"] = MonitorFrame(self.main_content, self.controller)
        self.frames["settings"] = SettingsFrame(self.main_content, self.controller)
        
        # Create user management frame only for admin users
        if self.controller.user_role.lower() == "admin":
            self.frames["users"] = UserManagementFrame(self.main_content, self.controller)
        
        # Show home frame initially
        self.show_frame("home")
    
    def create_sidebar(self):
        # Sidebar setup
        self.sidebar = ctk.CTkFrame(
            self.container,
            width=self.sidebar_width,
            corner_radius=0,
            fg_color="#1F1F1F"
        )
        self.sidebar.pack(side="left", fill="y")
        
        # Load icons
        self.load_icons()
        
        # Logo at top
        ctk.CTkLabel(
            self.sidebar,
            image=self.logo_image,
            text=""
        ).pack(pady=(15, 30))
        
        # Add buttons with underlines
        self.add_icon_button_with_line(self.home_image, "Home", lambda: self.show_frame("home"))
        self.add_icon_button_with_line(self.chat_image, "Chat", lambda: self.show_frame("chat"))
        self.add_icon_button_with_line(self.monitor_image, "Monitor", lambda: self.show_frame("monitor"))
        self.add_icon_button_with_line(self.dashboard_image, "Dashboards", self.open_dashboard)
        self.add_icon_button_with_line(self.settings_image, "Settings", lambda: self.show_frame("settings"))
        
        # Only show Users button for admin users (case-insensitive check)
        if self.controller.user_role.lower() == "admin":
            self.add_icon_button_with_line(self.user_image, "Users", lambda: self.show_frame("users"))
        
        # Spacer before logout
        ctk.CTkLabel(self.sidebar, text="", fg_color="#1F1F1F").pack(expand=True)
        
        # Logout button
        ctk.CTkButton(
            master=self.sidebar,
            image=self.logout_image,
            text="Logout",
            command=self.logout,
            fg_color="transparent",
            hover_color="#2E2E2E",
            text_color="white",
            compound="top",
            font=("Arial", 15),
            width=self.sidebar_width,
            height=self.icon_size + 20
        ).pack(pady=(0, 20))
    
    def load_icons(self):
        # Load all icons
        logo_width = int(35 * 1.5)  # Base width
        logo_height = int(35 * 2)   # Taller height
        self.logo_image = ctk.CTkImage(
            Image.open("/home/zalma/Downloads/watchtower/watchtower/icons/logo.png"),
            size=(logo_width, logo_height)  # Width: 35*1.5, Height: 35*2
        )
        self.home_image = ctk.CTkImage(
            Image.open("/home/zalma/Downloads/watchtower/watchtower/icons/home.png"),
            size=(self.icon_size, self.icon_size)
        )
        self.chat_image = ctk.CTkImage(
            Image.open("/home/zalma/Downloads/watchtower/watchtower/icons/chat.png"),
            size=(self.icon_size, self.icon_size)
        )
        self.monitor_image = ctk.CTkImage(
            Image.open("/home/zalma/Downloads/watchtower/watchtower/icons/monitor.png"),
            size=(self.icon_size, self.icon_size)
        )
        self.dashboard_image = ctk.CTkImage(
            Image.open("/home/zalma/Downloads/watchtower/watchtower/icons/dashboard.png"),
            size=(self.icon_size, self.icon_size)
        )
        self.settings_image = ctk.CTkImage(
            Image.open("/home/zalma/Downloads/watchtower/watchtower/icons/settings.png"),
            size=(self.icon_size, self.icon_size)
        )
        # Make users management icon 1.4 times bigger than other icons
        users_icon_size = int(self.icon_size * 1.4)
        self.user_image = ctk.CTkImage(
            Image.open("/home/zalma/Downloads/watchtower/watchtower/icons/usersManagement.png"),
            size=(users_icon_size, users_icon_size)
        )
        self.logout_image = ctk.CTkImage(
            Image.open("/home/zalma/Downloads/watchtower/watchtower/icons/logout.png"),
            size=(self.icon_size, self.icon_size)
        )
    
    def add_icon_button_with_line(self, image, text, command):
        btn = ctk.CTkButton(
            self.sidebar,
            image=image,
            text=text,
            command=command,
            fg_color="transparent",
            hover_color="#2E2E2E",
            text_color="white",
            compound="top",
            font=("Arial", 15),
            width=self.sidebar_width,
            height=self.icon_size + 20
        )
        btn.pack(pady=15)  # Increased padding from 5 to 15
        
        ctk.CTkFrame(
            self.sidebar,
            height=2,
            fg_color="#2E2E2E"
        ).pack(fill="x", padx=20)
    
    def show_frame(self, frame_name):
        # Hide all frames
        for frame in self.frames.values():
            frame.pack_forget()
        
        # Show selected frame
        frame = self.frames.get(frame_name)
        if frame:
            print(f"Showing {frame_name} frame")
            frame.pack(fill="both", expand=True)
        else:
            print(f"Frame {frame_name} not found")
    
    def open_dashboard(self):
        # Create webview window
        webview.create_window("WatchTower Dashboard", 
                            url="http://127.0.0.1:8051",
                            width=1920,
                            height=1080,
                            resizable=True)
        webview.start()
    
    def logout(self):
        try:
            # Close any active database connections
            if hasattr(self, 'frames') and 'chat' in self.frames:
                chat_frame = self.frames['chat']
                if hasattr(chat_frame, 'conn') and chat_frame.conn:
                    chat_frame.conn.close()
                if hasattr(chat_frame, 'sio') and chat_frame.sio.connected:
                    chat_frame.sio.disconnect()

            # Stop monitoring in monitor frame
            if hasattr(self, 'frames') and 'monitor' in self.frames:
                monitor_frame = self.frames['monitor']
                if hasattr(monitor_frame, 'should_stop'):
                    monitor_frame.should_stop = True

            # Reset user data
            self.controller.username = None
            self.controller.user_role = None
            
            # Show login screen
            self.controller.show_login()
            
        except Exception as e:
            print(f"Error during logout: {e}")
            # Still try to show login screen even if cleanup fails
            self.controller.show_login()

if __name__ == "__main__":
    app = WatchTowerApp()
    app.mainloop()
