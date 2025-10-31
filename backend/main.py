from fastapi import FastAPI, Depends, HTTPException, status, Body, WebSocket, WebSocketDisconnect, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
from typing import List, Optional
import asyncio
from slack_sdk import WebClient

# Database imports
from database import database, create_tables
from crud import (
    create_agent_data, get_latest_agent_data, get_all_agent_data,
    create_user, get_user_by_username, get_user_by_email, get_user_by_id,
    update_user_last_login, update_user_role, disable_user, enable_user,
    get_all_users, update_user_password
)

app = FastAPI(title="PurpleTeam Dashboard Backend")

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Manual CORS headers as backup
@app.middleware("http")
async def add_cors_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "*"
    response.headers["Access-Control-Allow-Credentials"] = "true"
    return response

# Handle OPTIONS requests for CORS preflight
@app.options("/{rest_of_path:path}")
async def preflight_handler(request: Request, rest_of_path: str):
    response = JSONResponse(content={"message": "CORS preflight"})
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "*"
    return response

# Database connection events
@app.on_event("startup")
async def startup():
    await database.connect()
    create_tables()
    
    # Create default admin user if it doesn't exist
    admin_user = await get_user_by_username("admin")
    if not admin_user:
        await create_user(
            username="admin",
            email="admin@purpleteam.com",
            password="adminpass",
            role="admin"
        )
        print("✅ Default admin user created")
    
    print("✅ Database connected successfully!")

@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()
    print("✅ Database disconnected successfully!")

SECRET_KEY = "your-secret-key-change-in-production-12345"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Slack configuration
slack_token = "xoxb-your-slack-token-here"
client = WebClient(token=slack_token)

def send_slack_alert(message: str):
    try:
        client.chat_postMessage(channel="#alerts", text=message)
        print(f"Slack alert sent: {message}")
    except Exception as e:
        print(f"Failed to send Slack alert: {e}")

# Using Argon2 for modern password hashing
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        print(f"New WebSocket connection. Total connections: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        print(f"WebSocket disconnected. Total connections: {len(self.active_connections)}")

    async def broadcast(self, message: dict):
        if self.active_connections:
            disconnected = []
            for connection in self.active_connections:
                try:
                    await connection.send_json(message)
                except Exception:
                    disconnected.append(connection)
            
            for connection in disconnected:
                self.disconnect(connection)

manager = ConnectionManager()

# Pydantic Models
class UserBase(BaseModel):
    username: str
    email: Optional[str] = None
    role: str = "guest"
    disabled: Optional[bool] = None

class UserCreate(BaseModel):
    username: str
    email: str
    password: str
    role: str = "guest"

class UserUpdate(BaseModel):
    email: Optional[str] = None
    role: Optional[str] = None
    disabled: Optional[bool] = None

class User(UserBase):
    id: int
    created_at: Optional[datetime] = None
    last_login: Optional[datetime] = None

    class Config:
        from_attributes = True

class UserInDB(User):
    hashed_password: str

class Token(BaseModel):
    access_token: str
    token_type: str
    user: User

class PasswordChange(BaseModel):
    current_password: str
    new_password: str

# Authentication functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

async def authenticate_user(username: str, password: str):
    user = await get_user_by_username(username)
    if not user:
        # Also try email
        user = await get_user_by_email(username)
        if not user:
            return False
    
    user_dict = dict(user)
    if not verify_password(password, user_dict["hashed_password"]):
        return False
    
    if user_dict["disabled"]:
        return False
    
    # Update last login
    await update_user_last_login(user_dict["id"])
    
    return UserInDB(**user_dict)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"})
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    user = await get_user_by_username(username)
    if user is None:
        raise credentials_exception
    
    user_dict = dict(user)
    if user_dict["disabled"]:
        raise HTTPException(status_code=400, detail="Inactive user")
    
    return User(**user_dict)

async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

# Role-based access control dependencies
def require_role(required_role: str):
    async def role_checker(current_user: User = Depends(get_current_active_user)):
        if current_user.role != required_role and current_user.role != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires {required_role} role"
            )
        return current_user
    return role_checker

def require_any_role(required_roles: List[str]):
    async def role_checker(current_user: User = Depends(get_current_active_user)):
        if current_user.role not in required_roles and current_user.role != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires one of these roles: {', '.join(required_roles)}"
            )
        return current_user
    return role_checker

# Specific role checkers
get_admin_user = require_role("admin")
get_agent_user = require_any_role(["agent", "admin"])
get_guest_user = require_any_role(["guest", "agent", "admin"])

# Authentication routes
@app.post("/register", response_model=User)
async def register_user(user_data: UserCreate):
    """
    Register a new user
    """
    # Check if username already exists
    existing_user = await get_user_by_username(user_data.username)
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered"
        )
    
    # Check if email already exists
    existing_email = await get_user_by_email(user_data.email)
    if existing_email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    # Only allow certain roles for self-registration
    if user_data.role not in ["guest", "agent"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid role for self-registration"
        )
    
    user_id = await create_user(
        username=user_data.username,
        email=user_data.email,
        password=user_data.password,
        role=user_data.role
    )
    
    # Get the created user
    user = await get_user_by_id(user_id)
    return User(**dict(user))

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await authenticate_user(form_data.username, form_data.password)
    if not user:
        send_slack_alert(f"🚨 Failed login attempt for username: {form_data.username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    send_slack_alert(f"✅ Successful login for user: {user.username} (Role: {user.role})")
    
    access_token = create_access_token(
        data={"sub": user.username},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    
    return {
        "access_token": access_token, 
        "token_type": "bearer",
        "user": user
    }

@app.get("/users/me", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user

@app.put("/users/me/password")
async def change_password(
    password_data: PasswordChange,
    current_user: User = Depends(get_current_active_user)
):
    """
    Change current user's password
    """
    # Verify current password
    user_db = await get_user_by_username(current_user.username)
    user_dict = dict(user_db)
    
    if not verify_password(password_data.current_password, user_dict["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect"
        )
    
    # Update password
    await update_user_password(current_user.id, password_data.new_password)
    
    return {"message": "Password updated successfully"}

# Admin-only routes
@app.get("/admin/users", response_model=List[User])
async def get_all_users_admin(current_user: User = Depends(get_admin_user)):
    """
    Get all users (Admin only)
    """
    users_data = await get_all_users()
    return [User(**dict(user)) for user in users_data]

@app.put("/admin/users/{user_id}/role")
async def update_user_role_admin(
    user_id: int, 
    role_update: dict = Body(...),
    current_user: User = Depends(get_admin_user)
):
    """
    Update user role (Admin only)
    """
    new_role = role_update.get("role")
    if new_role not in ["guest", "agent", "admin"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid role"
        )
    
    await update_user_role(user_id, new_role)
    return {"message": f"User role updated to {new_role}"}

@app.put("/admin/users/{user_id}/disable")
async def disable_user_admin(user_id: int, current_user: User = Depends(get_admin_user)):
    """
    Disable a user (Admin only)
    """
    await disable_user(user_id)
    return {"message": "User disabled"}

@app.put("/admin/users/{user_id}/enable")
async def enable_user_admin(user_id: int, current_user: User = Depends(get_admin_user)):
    """
    Enable a user (Admin only)
    """
    await enable_user(user_id)
    return {"message": "User enabled"}

# Agent data routes with role-based access
@app.post("/agent/data", status_code=201)
async def receive_agent_data(
    data: dict = Body(...), 
    current_user: User = Depends(get_agent_user)
):
    """
    Receive periodic data from agent (Agent/Admin only)
    """
    if 'timestamp' not in data:
        data['timestamp'] = datetime.utcnow().isoformat() + 'Z'
    
    data_id = await create_agent_data(data)
    
    check_critical_conditions(data)
    
    await manager.broadcast({
        "type": "agent_data_update",
        "data": data,
        "data_id": data_id,
        "timestamp": datetime.utcnow().isoformat() + 'Z'
    })
    
    return {"message": "Agent data received", "data_id": data_id}

def check_critical_conditions(data: dict):
    """Check agent data for critical conditions and send Slack alerts"""
    cpu_usage = data.get('cpu_usage', 0)
    if cpu_usage > 90:
        send_slack_alert(f"🚨 High CPU Usage Alert: {cpu_usage:.1f}% on {data.get('hostname', 'unknown')}")
    
    memory_usage = data.get('memory_usage', 0)
    if memory_usage > 90:
        send_slack_alert(f"🚨 High Memory Usage Alert: {memory_usage:.1f}% on {data.get('hostname', 'unknown')}")
    
    disk_usage = data.get('disk_usage', 0)
    if disk_usage > 90:
        send_slack_alert(f"🚨 High Disk Usage Alert: {disk_usage:.1f}% on {data.get('hostname', 'unknown')}")
    
    processes = data.get('processes', [])
    suspicious_processes = [p for p in processes if is_suspicious_process(p.get('name', ''))]
    if suspicious_processes:
        process_names = [p.get('name') for p in suspicious_processes]
        send_slack_alert(f"⚠️ Suspicious processes detected: {', '.join(process_names)} on {data.get('hostname', 'unknown')}")

def is_suspicious_process(process_name: str) -> bool:
    """Check if a process name is suspicious"""
    suspicious_keywords = ['miner', 'backdoor', 'malware', 'ransomware', 'keylogger', 'rootkit', 'trojan']
    return any(keyword in process_name.lower() for keyword in suspicious_keywords)

@app.get("/agent/data/latest")
async def get_latest_agent_data_endpoint(current_user: User = Depends(get_guest_user)):
    """
    Return latest agent data entry (Any authenticated user)
    """
    data = await get_latest_agent_data()
    if not data:
        return {"data": None}
    
    data_dict = dict(data)
    if data_dict.get('timestamp') and isinstance(data_dict['timestamp'], datetime):
        data_dict['timestamp'] = data_dict['timestamp'].isoformat() + 'Z'
    
    return {"data": data_dict}

@app.get("/agent/data")
async def get_all_agent_data_endpoint(current_user: User = Depends(get_guest_user)):
    """
    Return all agent data entries (Any authenticated user)
    """
    data = await get_all_agent_data()
    
    data_list = []
    for item in data:
        item_dict = dict(item)
        if item_dict.get('timestamp') and isinstance(item_dict['timestamp'], datetime):
            item_dict['timestamp'] = item_dict['timestamp'].isoformat() + 'Z'
        data_list.append(item_dict)
    
    return {"data": data_list}

@app.get("/agent/data/count")
async def get_agent_data_count(current_user: User = Depends(get_guest_user)):
    """
    Return count of agent data entries (Any authenticated user)
    """
    data = await get_all_agent_data()
    return {"count": len(data)}

@app.post("/slack/test")
async def test_slack_alert(current_user: User = Depends(get_agent_user)):
    """Test Slack alert functionality (Agent/Admin only)"""
    test_message = f"🧪 Test alert from PurpleTeam Dashboard - {datetime.utcnow().isoformat()}"
    send_slack_alert(test_message)
    return {"message": "Slack test alert sent"}

# WebSocket endpoint
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        # Get initial data for WebSocket connection
        all_data = await get_all_agent_data()
        latest_data = await get_latest_agent_data()
        
        # Convert latest_data timestamp for frontend
        latest_data_dict = None
        if latest_data:
            latest_data_dict = dict(latest_data)
            if latest_data_dict.get('timestamp') and isinstance(latest_data_dict['timestamp'], datetime):
                latest_data_dict['timestamp'] = latest_data_dict['timestamp'].isoformat() + 'Z'
        
        await websocket.send_json({
            "type": "connection_established",
            "message": "Connected to PurpleTeam WebSocket",
            "active_connections": len(manager.active_connections),
            "timestamp": datetime.utcnow().isoformat() + 'Z'
        })
        
        await websocket.send_json({
            "type": "initial_data",
            "total_agent_data": len(all_data),
            "latest_data": latest_data_dict,
            "timestamp": datetime.utcnow().isoformat() + 'Z'
        })
        
        while True:
            # Wait for messages from client
            data = await websocket.receive_text()
            await manager.broadcast({
                "type": "client_message",
                "message": f"Client says: {data}",
                "timestamp": datetime.utcnow().isoformat() + 'Z'
            })
            
    except WebSocketDisconnect:
        manager.disconnect(websocket)

@app.get("/ws/status")
async def websocket_status():
    """Get WebSocket connection status"""
    all_data = await get_all_agent_data()
    return {
        "active_connections": len(manager.active_connections),
        "total_agent_data": len(all_data)
    }

@app.get("/")
async def root():
    return {"message": "PurpleTeam Dashboard Backend Online"}

@app.get("/health")
async def health_check():
    """Health check endpoint - No auth required for testing"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat() + 'Z',
        "database_connected": True
    }

# Background task to simulate real-time updates
@app.on_event("startup")
async def startup_event():
    async def simulate_updates():
        while True:
            await asyncio.sleep(30)
            if manager.active_connections:
                await manager.broadcast({
                    "type": "heartbeat",
                    "message": "Server is alive",
                    "timestamp": datetime.utcnow().isoformat() + 'Z',
                    "active_connections": len(manager.active_connections)
                })
    
    asyncio.create_task(simulate_updates())

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
