# database.py - Fixed schema with all required columns
import os
import databases
import sqlalchemy
from sqlalchemy import create_engine, MetaData
from sqlalchemy import Table, Column, Integer, String, Boolean, DateTime, Text, JSON, Float, ForeignKey
from sqlalchemy.sql import func

# Database configuration
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./purpleteam.db")

# Create database connection
database = databases.Database(DATABASE_URL)
metadata = MetaData()

# For SQLite, we need to set check_same_thread to False
if DATABASE_URL.startswith("sqlite"):
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
else:
    engine = create_engine(DATABASE_URL)

# Define ALL tables including new monitoring tables
users = Table(
    "users",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("username", String(50), unique=True, index=True),
    Column("email", String(100), unique=True, index=True),
    Column("hashed_password", String(255)),
    Column("role", String(20), default="guest"),
    Column("disabled", Boolean, default=False),
    Column("email_verified", Boolean, default=False),  # Added missing column
    Column("full_name", String(100), nullable=True),
    Column("department", String(100), nullable=True),
    Column("phone_number", String(20), nullable=True),
    Column("metadata", JSON, nullable=True),
    Column("login_count", Integer, default=0),
    Column("last_login", DateTime, nullable=True),
    Column("last_login_ip", String(45), nullable=True),
    Column("password_changed_at", DateTime, nullable=True),
    Column("force_password_change", Boolean, default=False),
    Column("disabled_at", DateTime, nullable=True),
    Column("created_at", DateTime, default=func.now()),
    Column("updated_at", DateTime, default=func.now(), onupdate=func.now())
)

# New servers table for multi-server monitoring
servers = Table(
    "servers",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("hostname", String(100), unique=True, index=True),
    Column("ip_address", String(45)),  # IPv6 compatible
    Column("description", Text),
    Column("os_type", String(50)),  # linux, windows, macos
    Column("os_version", String(50)),
    Column("tags", JSON),  # Custom tags for grouping
    Column("monitoring_enabled", Boolean, default=True),
    Column("location", String(100), nullable=True),
    Column("environment", String(50), default="production"),
    Column("criticality", String(20), default="medium"),
    Column("status", String(20), default="unknown"),
    Column("created_by", Integer, ForeignKey('users.id'), nullable=True),
    Column("created_at", DateTime, default=func.now()),
    Column("updated_at", DateTime, default=func.now(), onupdate=func.now()),
    Column("last_seen", DateTime, nullable=True)
)

agent_data = Table(
    "agent_data",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("server_id", Integer, ForeignKey('servers.id'), nullable=True),  # Fixed: added server_id
    Column("data", JSON),
    Column("timestamp", DateTime),
    Column("hostname", String(100), nullable=True),
    Column("agent_version", String(50), nullable=True),
    Column("created_at", DateTime, default=func.now())
)

# Alerting tables
alert_rules = Table(
    "alert_rules",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("server_id", Integer, ForeignKey('servers.id'), nullable=True),  # NULL means global rule
    Column("metric", String(50), nullable=False),
    Column("threshold_value", Float, nullable=False),
    Column("comparison_operator", String(5), nullable=False),
    Column("severity", String(20), default="medium"),
    Column("active", Boolean, default=True),
    Column("description", Text),
    Column("duration_threshold", Integer, default=0),
    Column("cooldown_period", Integer, default=300),
    Column("tags", JSON, nullable=True),
    Column("created_by", Integer, ForeignKey('users.id')),
    Column("created_at", DateTime, default=func.now()),
    Column("updated_at", DateTime, default=func.now(), onupdate=func.now())
)

incidents = Table(
    "incidents",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("server_id", Integer, ForeignKey('servers.id'), nullable=True),
    Column("alert_rule_id", Integer, ForeignKey('alert_rules.id'), nullable=True),
    Column("agent_data_id", Integer, ForeignKey('agent_data.id'), nullable=True),
    Column("incident_type", String(100)),
    Column("message", Text),
    Column("severity", String(20), default="medium"),
    Column("status", String(20), default="open"),
    Column("metadata", JSON),
    Column("comments", JSON, nullable=True),
    Column("created_at", DateTime, default=func.now()),
    Column("acknowledged_by", Integer, ForeignKey('users.id'), nullable=True),
    Column("acknowledged_at", DateTime, nullable=True),
    Column("resolved_by", Integer, ForeignKey('users.id'), nullable=True),
    Column("resolved_at", DateTime, nullable=True),
    Column("resolved_notes", Text, nullable=True),
    Column("updated_at", DateTime, default=func.now(), onupdate=func.now())
)

# New user activity tracking table
user_activity = Table(
    "user_activity",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("user_id", Integer, ForeignKey('users.id'), nullable=True),
    Column("username", String(50)),  # Store username separately in case user is deleted
    Column("activity_type", String(50)),  # login, logout, password_change, etc.
    Column("ip_address", String(45)),
    Column("user_agent", Text),
    Column("success", Boolean, default=True),
    Column("details", JSON),  # Additional context like failed reason, changed settings
    Column("session_id", String(100), nullable=True),
    Column("country", String(100), nullable=True),
    Column("city", String(100), nullable=True),
    Column("created_at", DateTime, default=func.now())
)

# New visitor/request monitoring table
visitor_logs = Table(
    "visitor_logs",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("user_id", Integer, ForeignKey('users.id'), nullable=True),  # Added missing column
    Column("ip_address", String(45)),
    Column("user_agent", Text),
    Column("request_method", String(10)),
    Column("request_path", String(500)),
    Column("request_query", JSON),  # Query parameters
    Column("request_headers", JSON),
    Column("request_body", Text, nullable=True),
    Column("response_status", Integer),
    Column("response_size", Integer),
    Column("processing_time", Float),  # Request processing time in ms
    Column("suspicious", Boolean, default=False),
    Column("suspicious_reason", Text, nullable=True),
    Column("country", String(100), nullable=True),
    Column("city", String(100), nullable=True),
    Column("created_at", DateTime, default=func.now())
)

# Dashboard layouts
user_dashboard_layouts = Table(
    "user_dashboard_layouts",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("user_id", Integer, ForeignKey('users.id')),
    Column("name", String(100), default="Default Layout"),
    Column("layout", JSON),  # Store the grid layout
    Column("widgets", JSON), # Store widget configurations
    Column("filters", JSON), # Store saved filter presets
    Column("is_default", Boolean, default=False),
    Column("created_at", DateTime, default=func.now()),
    Column("updated_at", DateTime, default=func.now(), onupdate=func.now())
)

# NEW TABLES FOR ENHANCED FEATURES

# AI Insights table
ai_insights = Table(
    "ai_insights",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("metric_type", String(50)),
    Column("insight_type", String(20)),  # warning, info, success, critical
    Column("message", Text),
    Column("confidence", Float),
    Column("action", String(100), nullable=True),
    Column("server_id", Integer, ForeignKey('servers.id'), nullable=True),
    Column("related_data_id", Integer, ForeignKey('agent_data.id'), nullable=True),
    Column("metadata", JSON, nullable=True),
    Column("created_at", DateTime, default=func.now())
)

# Server locations for global map
server_locations = Table(
    "server_locations",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("name", String(100)),
    Column("latitude", Float),
    Column("longitude", Float),
    Column("status", String(20), default="online"),
    Column("current_load", Float, default=0.0),
    Column("active_users", Integer, default=0),
    Column("server_id", Integer, ForeignKey('servers.id'), nullable=True),
    Column("description", Text, nullable=True),
    Column("tags", JSON, nullable=True),
    Column("last_updated", DateTime, default=func.now())
)

# User preferences table
user_preferences = Table(
    "user_preferences",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("user_id", Integer, ForeignKey('users.id')),
    Column("preference_type", String(50)),
    Column("preference_value", JSON),
    Column("created_at", DateTime, default=func.now()),
    Column("updated_at", DateTime, default=func.now(), onupdate=func.now())
)

# Notifications table
notifications = Table(
    "notifications",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("type", String(50)),
    Column("title", String(200)),
    Column("message", Text),
    Column("priority", String(20), default="medium"),
    Column("related_id", Integer, nullable=True),
    Column("metadata", JSON, nullable=True),
    Column("read", Boolean, default=False),
    Column("read_at", DateTime, nullable=True),
    Column("created_at", DateTime, default=func.now())
)

async def create_tables():
    """Create all tables that don't exist"""
    metadata.create_all(engine)
    print("✅ All database tables created/verified")

async def initialize_default_data():
    """Initialize default servers and data"""
    try:
        # Check if default server exists
        existing_server = await database.fetch_one(
            "SELECT id FROM servers WHERE hostname = 'default-server'"
        )
        
        if not existing_server:
            await database.execute(
                """
                INSERT INTO servers (hostname, ip_address, description, os_type, os_version, tags)
                VALUES (:hostname, :ip_address, :description, :os_type, :os_version, :tags)
                """,
                {
                    "hostname": "default-server",
                    "ip_address": "127.0.0.1",
                    "description": "Default monitoring server",
                    "os_type": "linux",
                    "os_version": "ubuntu-20.04",
                    "tags": '["default", "monitoring"]'
                }
            )
            print("✅ Default server created")
        
        # Create some sample servers for demonstration
        sample_servers = [
            {
                "hostname": "web-server-01",
                "ip_address": "192.168.1.101",
                "description": "Production web server",
                "os_type": "linux",
                "os_version": "ubuntu-22.04",
                "tags": '["web", "production", "nginx"]'
            },
            {
                "hostname": "db-server-01", 
                "ip_address": "192.168.1.102",
                "description": "Production database server",
                "os_type": "linux",
                "os_version": "ubuntu-22.04",
                "tags": '["database", "production", "postgresql"]'
            },
            {
                "hostname": "app-server-01",
                "ip_address": "192.168.1.103",
                "description": "Application server",
                "os_type": "linux", 
                "os_version": "centos-8",
                "tags": '["application", "production", "java"]'
            }
        ]
        
        for server in sample_servers:
            existing = await database.fetch_one(
                "SELECT id FROM servers WHERE hostname = :hostname",
                {"hostname": server["hostname"]}
            )
            if not existing:
                await database.execute(
                    """
                    INSERT INTO servers (hostname, ip_address, description, os_type, os_version, tags)
                    VALUES (:hostname, :ip_address, :description, :os_type, :os_version, :tags)
                    """,
                    server
                )
                print(f"✅ Sample server {server['hostname']} created")
                
    except Exception as e:
        print(f"⚠️ Default data initialization error: {e}")
