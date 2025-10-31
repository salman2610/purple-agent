import databases
import sqlalchemy
from sqlalchemy import MetaData, Table, Column, Integer, String, JSON, DateTime, Float, Boolean

# Database URL - using asyncpg for async support
DATABASE_URL = "postgresql+asyncpg://purpleteam_user:YourStrongPassword@localhost/purpleteam_db"

# Create database connection
database = databases.Database(DATABASE_URL)
metadata = MetaData()

# Define agent_data table
agent_data = Table(
    "agent_data",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("hostname", String(255)),
    Column("cpu_usage", Float),
    Column("memory_usage", Float),
    Column("disk_usage", Float),
    Column("processes", JSON),
    Column("timestamp", DateTime)
)

# Define users table
users = Table(
    "users",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("username", String(255), unique=True, index=True),
    Column("email", String(255), unique=True, index=True),
    Column("hashed_password", String(255)),
    Column("role", String(50), default="guest"),
    Column("disabled", Boolean, default=False),
    Column("created_at", DateTime, server_default=sqlalchemy.func.now()),
    Column("last_login", DateTime, nullable=True),
)

# For table creation, we need a sync connection
sync_database_url = DATABASE_URL.replace("+asyncpg", "")
engine = sqlalchemy.create_engine(sync_database_url)

def create_tables():
    """Create database tables"""
    try:
        metadata.create_all(engine)
        print("✅ Database tables created/verified")
    except Exception as e:
        print(f"❌ Error creating tables: {e}")
