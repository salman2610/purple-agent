# database.py - Add these table definitions
import os
import databases
import sqlalchemy
from sqlalchemy import create_engine, MetaData
from sqlalchemy import Table, Column, Integer, String, Boolean, DateTime, Text, JSON, Float
from sqlalchemy.sql import func

# Database configuration - Use SQLite with proper connection string
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./purpleteam.db")

# Create database connection
database = databases.Database(DATABASE_URL)
metadata = MetaData()

# For SQLite, we need to set check_same_thread to False
if DATABASE_URL.startswith("sqlite"):
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
else:
    engine = create_engine(DATABASE_URL)

# Define ALL tables including alerting tables
users = Table(
    "users",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("username", String(50), unique=True, index=True),
    Column("email", String(100), unique=True, index=True),
    Column("hashed_password", String(255)),
    Column("role", String(20), default="guest"),
    Column("disabled", Boolean, default=False),
    Column("created_at", DateTime, default=func.now()),
    Column("last_login", DateTime, nullable=True)
)

agent_data = Table(
    "agent_data",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("data", JSON),
    Column("timestamp", DateTime),
    Column("created_at", DateTime, default=func.now())
)

# ALERTING TABLES - FIXED with SQLite-compatible datetime defaults
alert_rules = Table(
    "alert_rules",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("metric", String(50), nullable=False),
    Column("threshold_value", Float, nullable=False),
    Column("comparison_operator", String(5), nullable=False),
    Column("severity", String(20), default="medium"),
    Column("active", Boolean, default=True),
    Column("description", Text),
    Column("created_by", Integer, sqlalchemy.ForeignKey('users.id')),
    Column("created_at", DateTime, default=func.now()),
    Column("updated_at", DateTime, default=func.now())
)

incidents = Table(
    "incidents",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("alert_rule_id", Integer, sqlalchemy.ForeignKey('alert_rules.id'), nullable=True),
    Column("agent_data_id", Integer, sqlalchemy.ForeignKey('agent_data.id'), nullable=True),
    Column("incident_type", String(100)),
    Column("message", Text),
    Column("severity", String(20), default="medium"),
    Column("status", String(20), default="new"),
    Column("metadata", JSON),
    Column("created_at", DateTime, default=func.now()),
    Column("acknowledged_by", Integer, sqlalchemy.ForeignKey('users.id'), nullable=True),
    Column("acknowledged_at", DateTime, nullable=True),
    Column("resolved_by", Integer, sqlalchemy.ForeignKey('users.id'), nullable=True),
    Column("resolved_at", DateTime, nullable=True),
    Column("resolved_notes", Text, nullable=True)
)

def create_tables():
    """Create all tables that don't exist"""
    metadata.create_all(engine)
    print("✅ Database tables created/verified")
