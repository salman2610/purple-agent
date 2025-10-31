from database import database, agent_data, users
from sqlalchemy import desc
from datetime import datetime
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")

# Agent data functions
async def create_agent_data(data: dict):
    # Parse timestamp string to datetime object
    timestamp_str = data.get('timestamp')
    if timestamp_str:
        # Handle ISO format with 'Z' timezone - convert to naive UTC datetime
        if timestamp_str.endswith('Z'):
            timestamp_str = timestamp_str.replace('Z', '+00:00')
        
        # Parse to timezone-aware datetime first
        timestamp_aware = datetime.fromisoformat(timestamp_str)
        
        # Convert to timezone-naive UTC by replacing timezone info
        timestamp = timestamp_aware.replace(tzinfo=None)
    else:
        # Use naive UTC datetime
        timestamp = datetime.utcnow()
    
    query = agent_data.insert().values(
        hostname=data.get('hostname'),
        cpu_usage=data.get('cpu_usage'),
        memory_usage=data.get('memory_usage'),
        disk_usage=data.get('disk_usage'),
        processes=data.get('processes', []),
        timestamp=timestamp
    )
    return await database.execute(query)

async def get_latest_agent_data():
    query = agent_data.select().order_by(desc(agent_data.c.id)).limit(1)
    return await database.fetch_one(query)

async def get_all_agent_data():
    query = agent_data.select().order_by(desc(agent_data.c.id))
    return await database.fetch_all(query)

# User management functions
async def create_user(username: str, email: str, password: str, role: str = "guest"):
    hashed_password = pwd_context.hash(password)
    query = users.insert().values(
        username=username,
        email=email,
        hashed_password=hashed_password,
        role=role,
        disabled=False
    )
    return await database.execute(query)

async def get_user_by_username(username: str):
    query = users.select().where(users.c.username == username)
    return await database.fetch_one(query)

async def get_user_by_email(email: str):
    query = users.select().where(users.c.email == email)
    return await database.fetch_one(query)

async def get_user_by_id(user_id: int):
    query = users.select().where(users.c.id == user_id)
    return await database.fetch_one(query)

async def update_user_last_login(user_id: int):
    query = users.update().where(users.c.id == user_id).values(
        last_login=datetime.utcnow()
    )
    return await database.execute(query)

async def update_user_role(user_id: int, role: str):
    query = users.update().where(users.c.id == user_id).values(role=role)
    return await database.execute(query)

async def disable_user(user_id: int):
    query = users.update().where(users.c.id == user_id).values(disabled=True)
    return await database.execute(query)

async def enable_user(user_id: int):
    query = users.update().where(users.c.id == user_id).values(disabled=False)
    return await database.execute(query)

async def get_all_users():
    query = users.select().order_by(users.c.username)
    return await database.fetch_all(query)

async def update_user_password(user_id: int, new_password: str):
    hashed_password = pwd_context.hash(new_password)
    query = users.update().where(users.c.id == user_id).values(
        hashed_password=hashed_password
    )
    return await database.execute(query)
