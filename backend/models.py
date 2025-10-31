from sqlalchemy import Table, Column, Integer, String, Boolean, Float, TIMESTAMP, JSON, text
from database import metadata

users = Table(
    "users", metadata,
    Column("id", Integer, primary_key=True),
    Column("username", String(50), unique=True, nullable=False),
    Column("hashed_password", String(255), nullable=False),
    Column("disabled", Boolean, default=False),
)

agent_data = Table(
    "agent_data", metadata,
    Column("id", Integer, primary_key=True),
    Column("timestamp", TIMESTAMP(timezone=True), nullable=False),
    Column("hostname", String(255), nullable=False),
    Column("cpu_usage", Float),
    Column("memory_usage", Float),
    Column("disk_usage", Float),
    Column("network_bytes_sent", Integer),
    Column("network_bytes_received", Integer),
    Column("processes", JSON),
    Column("suspicious_activity", JSON)
)

alerts = Table(
    "alerts", metadata,
    Column("id", Integer, primary_key=True),
    Column("timestamp", TIMESTAMP(timezone=True), server_default=text("now()")),
    Column("message", String, nullable=False),
    Column("acknowledged", Boolean, default=False)
)
