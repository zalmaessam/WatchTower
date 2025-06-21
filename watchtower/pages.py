import dash_bootstrap_components as dbc
from dash import html, dcc, Input, Output, State, callback
import plotly.express as px
from datetime import datetime
import pandas as pd

# Common styles
COMMON_STYLES = {
    "backgroundColor": "#121212",
    "color": "#BB86FC",
    "fontFamily": "Segoe UI",
    "padding": "2rem",
    "minHeight": "100vh"
}

def home_layout():
    return dbc.Container([
        html.Div([
            html.H1("Intrusion Detection System Analytics", style={
                "color": "#BB86FC",
                "fontFamily": "Segoe UI",
                "fontWeight": "bold",
                "marginTop": "1.5rem",
                "marginBottom": "2rem",
                "textAlign": "center",
                "textShadow": "0 0 10px #BB86FC"
            }),
        ]),

        dbc.Row([
            dbc.Col(id="total-alerts-card", width=3),
            dbc.Col(id="total-traffic-card", width=3),
            dbc.Col(id="total-dns-card", width=3),
            dbc.Col(id="top-attack-card", width=3),
        ], className="mb-5"),

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
    style=COMMON_STYLES)

def chat_layout():
    return dbc.Container([
        html.Div([
            html.H1("Chat", className="mb-4", style={
                "color": "#BB86FC",
                "fontFamily": "Segoe UI",
                "fontWeight": "bold",
            }),
            dbc.Row([
                # Contacts sidebar
                dbc.Col([
                    dbc.Input(
                        type="search",
                        placeholder="Search conversations...",
                        className="mb-3",
                        style={"backgroundColor": "#403F3F", "border": "none"}
                    ),
                    html.Div(id="contacts-list", style={"height": "calc(100vh - 200px)", "overflowY": "auto"})
                ], width=3, style={"backgroundColor": "#1b1b1b", "padding": "1rem"}),
                
                # Chat area
                dbc.Col([
                    html.Div(id="chat-messages", style={
                        "height": "calc(100vh - 200px)",
                        "overflowY": "auto",
                        "backgroundColor": "#131313",
                        "padding": "1rem"
                    }),
                    dbc.InputGroup([
                        dbc.Input(
                            id="message-input",
                            placeholder="Type a message...",
                            style={"backgroundColor": "#2a2a2a", "border": "none"}
                        ),
                        dbc.Button("Send", color="primary", id="send-button")
                    ], className="mt-3")
                ], width=9)
            ])
        ])
    ],
    fluid=True,
    style=COMMON_STYLES)

def tracking_layout():
    return dbc.Container([
        html.H1("Tracking", style={
            "color": "#BB86FC",
            "fontFamily": "Segoe UI",
            "fontWeight": "bold",
            "marginBottom": "2rem",
        }),
        dbc.Row([
            dbc.Col([
                dbc.Card([
                    dbc.CardHeader("Active Alerts"),
                    dbc.CardBody(id="active-alerts")
                ], className="mb-4")
            ], width=6),
            dbc.Col([
                dbc.Card([
                    dbc.CardHeader("System Status"),
                    dbc.CardBody(id="system-status")
                ], className="mb-4")
            ], width=6)
        ]),
        dbc.Row([
            dbc.Col([
                dcc.Graph(id="tracking-timeline")
            ])
        ])
    ],
    fluid=True,
    style=COMMON_STYLES)

def users_layout():
    return dbc.Container([
        html.H1("User Management", style={
            "color": "#BB86FC",
            "fontFamily": "Segoe UI",
            "fontWeight": "bold",
            "marginBottom": "2rem",
        }),
        dbc.Row([
            dbc.Col([
                dbc.Input(
                    type="search",
                    id="user-search",
                    placeholder="Search users...",
                    className="mb-4",
                    style={"backgroundColor": "#2a2a2a", "border": "none"}
                ),
                html.Div(id="users-table", style={"backgroundColor": "#1b1b1b", "padding": "1rem"}),
                dbc.ButtonGroup([
                    dbc.Button("Add User", color="primary", id="add-user-btn", className="me-2"),
                    dbc.Button("Delete Selected", color="danger", id="delete-users-btn", disabled=True)
                ], className="mt-4")
            ])
        ]),
        # Add User Modal
        dbc.Modal([
            dbc.ModalHeader("Add New User"),
            dbc.ModalBody([
                dbc.Input(id="new-user-firstname", placeholder="First Name", className="mb-3"),
                dbc.Input(id="new-user-lastname", placeholder="Last Name", className="mb-3"),
                dbc.Input(id="new-user-email", placeholder="Email", className="mb-3"),
                dbc.Input(id="new-user-username", placeholder="Username", className="mb-3"),
                dbc.Input(id="new-user-password", placeholder="Password", type="password", className="mb-3"),
                dbc.Select(
                    id="new-user-role",
                    options=[
                        {"label": "Admin", "value": "admin"},
                        {"label": "User", "value": "user"}
                    ],
                    placeholder="Select Role"
                )
            ]),
            dbc.ModalFooter([
                dbc.Button("Close", id="close-add-user-modal", className="me-2"),
                dbc.Button("Save", id="save-new-user", color="primary")
            ])
        ], id="add-user-modal")
    ],
    fluid=True,
    style=COMMON_STYLES)

def settings_layout():
    return dbc.Container([
        html.H1("Settings", style={
            "color": "#BB86FC",
            "fontFamily": "Segoe UI",
            "fontWeight": "bold",
            "marginBottom": "2rem",
        }),
        dbc.Row([
            dbc.Col([
                dbc.Card([
                    dbc.CardHeader("System Settings"),
                    dbc.CardBody([
                        dbc.FormGroup([
                            dbc.Label("Theme"),
                            dbc.Select(
                                id="theme-select",
                                options=[
                                    {"label": "Dark", "value": "dark"},
                                    {"label": "Light", "value": "light"}
                                ],
                                value="dark"
                            )
                        ], className="mb-3"),
                        dbc.FormGroup([
                            dbc.Label("Notification Settings"),
                            dbc.Checklist(
                                options=[
                                    {"label": "Email Notifications", "value": "email"},
                                    {"label": "Desktop Notifications", "value": "desktop"},
                                    {"label": "Sound Alerts", "value": "sound"}
                                ],
                                value=["desktop"],
                                id="notification-settings"
                            )
                        ], className="mb-3"),
                        dbc.Button("Save Settings", color="primary", id="save-settings")
                    ])
                ], style={"backgroundColor": "#1b1b1b"})
            ], width=6),
            dbc.Col([
                dbc.Card([
                    dbc.CardHeader("Account Settings"),
                    dbc.CardBody([
                        dbc.FormGroup([
                            dbc.Label("Change Password"),
                            dbc.Input(
                                type="password",
                                id="current-password",
                                placeholder="Current Password",
                                className="mb-2"
                            ),
                            dbc.Input(
                                type="password",
                                id="new-password",
                                placeholder="New Password",
                                className="mb-2"
                            ),
                            dbc.Input(
                                type="password",
                                id="confirm-password",
                                placeholder="Confirm New Password",
                                className="mb-3"
                            ),
                            dbc.Button("Update Password", color="primary", id="update-password")
                        ])
                    ])
                ], style={"backgroundColor": "#1b1b1b"})
            ], width=6)
        ])
    ],
    fluid=True,
    style=COMMON_STYLES) 