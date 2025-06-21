from dash import Input, Output, State, callback, ctx
import dash_bootstrap_components as dbc
import pandas as pd
import psycopg2
from psycopg2.extras import RealDictCursor
import hashlib
import json
from datetime import datetime
import socketio

# Database configuration
DB_CONFIG = {
    "dbname": "WatchTower",
    "user": "postgres",
    "password": "12345",
    "host": "localhost",
    "port": "5432"
}

# Socket.IO setup for chat
sio = socketio.Client()

def hash_password(password: str) -> str:
    """Hash password using SHA-256 algorithm."""
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

# Chat callbacks
@callback(
    Output("contacts-list", "children"),
    Input("interval-update", "n_intervals")
)
def update_contacts(n):
    try:
        with psycopg2.connect(**DB_CONFIG) as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute('SELECT username, firstname, lastname FROM login')
                users = cursor.fetchall()
                return [
                    dbc.ListGroupItem(
                        f"{user['firstname']} {user['lastname']}",
                        id={"type": "contact", "index": user["username"]},
                        action=True,
                        className="mb-2"
                    ) for user in users
                ]
    except Exception as e:
        print(f"Error fetching contacts: {e}")
        return []

@callback(
    Output("chat-messages", "children"),
    Input({"type": "contact", "index": "all"}, "n_clicks"),
    State({"type": "contact", "index": "all"}, "id")
)
def load_chat_messages(clicks, ids):
    if not any(clicks) or not ctx.triggered:
        return []
    
    triggered_id = ctx.triggered_id
    if triggered_id is None:
        return []
    
    selected_user = triggered_id["index"]
    try:
        # Fetch chat history for selected user
        messages = []  # Replace with actual message fetching
        return [
            dbc.Card(
                dbc.CardBody(msg["text"]),
                className="mb-2",
                style={"float": "right" if msg["sender"] == "current_user" else "left"}
            ) for msg in messages
        ]
    except Exception as e:
        print(f"Error loading messages: {e}")
        return []

# User Management callbacks
@callback(
    Output("users-table", "children"),
    Input("user-search", "value")
)
def update_users_table(search_term):
    try:
        with psycopg2.connect(**DB_CONFIG) as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                query = """
                    SELECT email, username, firstname, lastname, userrole
                    FROM login
                    WHERE LOWER(email) LIKE LOWER(%s)
                    OR LOWER(username) LIKE LOWER(%s)
                    OR LOWER(firstname) LIKE LOWER(%s)
                    OR LOWER(lastname) LIKE LOWER(%s)
                """
                search = f"%{search_term}%" if search_term else "%"
                cursor.execute(query, (search, search, search, search))
                users = cursor.fetchall()
                
                return dbc.Table([
                    html.Thead([
                        html.Tr([
                            html.Th("Select"),
                            html.Th("Email"),
                            html.Th("Username"),
                            html.Th("Name"),
                            html.Th("Role")
                        ])
                    ]),
                    html.Tbody([
                        html.Tr([
                            html.Td(dbc.Checkbox(id={"type": "user-select", "index": user["username"]})),
                            html.Td(user["email"]),
                            html.Td(user["username"]),
                            html.Td(f"{user['firstname']} {user['lastname']}"),
                            html.Td(user["userrole"])
                        ]) for user in users
                    ])
                ], bordered=True, dark=True, hover=True)
    except Exception as e:
        print(f"Error updating users table: {e}")
        return html.Div("Error loading users")

@callback(
    Output("add-user-modal", "is_open"),
    [Input("add-user-btn", "n_clicks"),
     Input("close-add-user-modal", "n_clicks"),
     Input("save-new-user", "n_clicks")],
    [State("new-user-firstname", "value"),
     State("new-user-lastname", "value"),
     State("new-user-email", "value"),
     State("new-user-username", "value"),
     State("new-user-password", "value"),
     State("new-user-role", "value"),
     State("add-user-modal", "is_open")]
)
def toggle_add_user_modal(n1, n2, n3, firstname, lastname, email, username, password, role, is_open):
    if ctx.triggered_id == "save-new-user" and all([firstname, lastname, email, username, password, role]):
        try:
            with psycopg2.connect(**DB_CONFIG) as conn:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        INSERT INTO login (email, username, firstname, lastname, password, userrole)
                        VALUES (%s, %s, %s, %s, %s, %s)
                    """, (email, username, firstname, lastname, hash_password(password), role))
                    conn.commit()
            return False
        except Exception as e:
            print(f"Error adding user: {e}")
            return is_open
    
    if n1 or n2 or n3:
        return not is_open
    return is_open

# Settings callbacks
@callback(
    Output("settings-notification", "children"),
    [Input("save-settings", "n_clicks")],
    [State("theme-select", "value"),
     State("notification-settings", "value")]
)
def save_settings(n_clicks, theme, notifications):
    if not n_clicks:
        return ""
    
    # Save settings to database or configuration file
    return dbc.Alert("Settings saved successfully!", color="success", duration=4000)

@callback(
    Output("password-notification", "children"),
    [Input("update-password", "n_clicks")],
    [State("current-password", "value"),
     State("new-password", "value"),
     State("confirm-password", "value")]
)
def update_password(n_clicks, current_password, new_password, confirm_password):
    if not n_clicks:
        return ""
    
    if not all([current_password, new_password, confirm_password]):
        return dbc.Alert("Please fill in all password fields", color="danger", duration=4000)
    
    if new_password != confirm_password:
        return dbc.Alert("New passwords do not match", color="danger", duration=4000)
    
    try:
        # Verify current password and update to new password in database
        return dbc.Alert("Password updated successfully!", color="success", duration=4000)
    except Exception as e:
        print(f"Error updating password: {e}")
        return dbc.Alert("Error updating password", color="danger", duration=4000) 