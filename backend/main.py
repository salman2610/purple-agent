from fastapi import FastAPI, Depends, HTTPException, status, Body, WebSocket, WebSocketDisconnect
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
from typing import List
import asyncio
from slack_sdk import WebClient

app = FastAPI(title="PurpleTeam Dashboard Backend")

# Allow React frontend origin (adjust if you deploy differently)
origins = [
    "http://localhost:5173",
    "http://localhost:5174",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:5174"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Slack configuration
slack_token = "your-slack-bot-token"
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

# Static pre-hashed password - no re-hashing at runtime
fake_users_db = {
    "admin": {
        "username": "admin",
        "hashed_password": "$argon2id$v=19$m=65536,t=3,p=4$25szRkhJKWVsrXUuJQRAKA$LnHX/YisT/KXpuN6CRyg0+fmLgOB86To5uIpK3LgDIw",
        "disabled": False,
    }
}

# In-memory storage for agent data (for demo; replace with DB later)
agent_data_store = []

# WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        print(f"New WebSocket connection. Total connections: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
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
            
            # Remove disconnected clients
            for connection in disconnected:
                self.disconnect(connection)

manager = ConnectionManager()

class Token(BaseModel):
    access_token: str
    token_type: str

class User(BaseModel):
    username: str
    disabled: bool | None = None

class UserInDB(User):
    hashed_password: str

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)

def authenticate_user(db, username: str, password: str):
    user = get_user(db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: timedelta | None = None):
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
    user = get_user(fake_users_db, username)
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user:
        # Send Slack alert for failed login attempt
        send_slack_alert(f"🚨 Failed login attempt for username: {form_data.username}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect username or password")
    
    # Send Slack alert for successful login
    send_slack_alert(f"✅ Successful login for user: {user.username}")
    
    access_token = create_access_token(data={"sub": user.username},
                                       expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user

@app.post("/agent/data", status_code=201)
async def receive_agent_data(data: dict = Body(...), current_user=Depends(get_current_active_user)):
    """
    Receive periodic data from agent.
    """
    agent_data_store.append(data)
    
    # Check for critical conditions and send Slack alerts
    check_critical_conditions(data)
    
    # Broadcast new agent data to all WebSocket clients
    await manager.broadcast({
        "type": "agent_data_update",
        "data": data,
        "total_entries": len(agent_data_store),
        "timestamp": datetime.utcnow().isoformat()
    })
    
    return {"message": "Agent data received", "data_id": len(agent_data_store) - 1}

def check_critical_conditions(data: dict):
    """Check agent data for critical conditions and send Slack alerts"""
    # Check high CPU usage
    cpu_usage = data.get('cpu_usage', 0)
    if cpu_usage > 90:
        send_slack_alert(f"🚨 High CPU Usage Alert: {cpu_usage:.1f}% on {data.get('hostname', 'unknown')}")
    
    # Check high memory usage
    memory_usage = data.get('memory_usage', 0)
    if memory_usage > 90:
        send_slack_alert(f"🚨 High Memory Usage Alert: {memory_usage:.1f}% on {data.get('hostname', 'unknown')}")
    
    # Check high disk usage
    disk_usage = data.get('disk_usage', 0)
    if disk_usage > 90:
        send_slack_alert(f"🚨 High Disk Usage Alert: {disk_usage:.1f}% on {data.get('hostname', 'unknown')}")
    
    # Check for suspicious processes
    processes = data.get('processes', [])
    suspicious_processes = [p for p in processes if is_suspicious_process(p.get('name', ''))]
    if suspicious_processes:
        process_names = [p.get('name') for p in suspicious_processes]
        send_slack_alert(f"⚠️ Suspicious processes detected: {', '.join(process_names)} on {data.get('hostname', 'unknown')}")

def is_suspicious_process(process_name: str) -> bool:
    """Check if a process name is suspicious"""
    suspicious_keywords = ['miner', 'backdoor', 'malware', 'ransomware', 'keylogger']
    return any(keyword in process_name.lower() for keyword in suspicious_keywords)

@app.get("/agent/data/latest")
async def get_latest_agent_data(current_user=Depends(get_current_active_user)):
    """
    Return latest agent data entry.
    """
    if not agent_data_store:
        return {"data": None}
    return {"data": agent_data_store[-1]}

@app.get("/agent/data")
async def get_all_agent_data(current_user=Depends(get_current_active_user)):
    """
    Return all agent data entries.
    """
    return {"data": agent_data_store}

@app.post("/slack/test")
async def test_slack_alert(current_user=Depends(get_current_active_user)):
    """Test Slack alert functionality"""
    test_message = f"🧪 Test alert from PurpleTeam Dashboard - {datetime.utcnow().isoformat()}"
    send_slack_alert(test_message)
    return {"message": "Slack test alert sent"}

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        # Send initial connection confirmation
        await websocket.send_json({
            "type": "connection_established",
            "message": "Connected to PurpleTeam WebSocket",
            "active_connections": len(manager.active_connections)
        })
        
        # Send current agent data count
        await websocket.send_json({
            "type": "initial_data",
            "total_agent_data": len(agent_data_store),
            "latest_data": agent_data_store[-1] if agent_data_store else None
        })
        
        while True:
            # Wait for messages from client (optional)
            data = await websocket.receive_text()
            
            # Echo back or process client message
            await manager.broadcast({
                "type": "client_message",
                "message": f"Client says: {data}",
                "timestamp": datetime.utcnow().isoformat()
            })
            
    except WebSocketDisconnect:
        manager.disconnect(websocket)

@app.get("/ws/status")
async def websocket_status():
    """Get WebSocket connection status"""
    return {
        "active_connections": len(manager.active_connections),
        "total_agent_data": len(agent_data_store)
    }

@app.get("/")
async def root():
    return {"message": "PurpleTeam Dashboard Backend Online"}

# Background task to simulate real-time updates (optional)
@app.on_event("startup")
async def startup_event():
    async def simulate_updates():
        while True:
            await asyncio.sleep(30)  # Every 30 seconds
            if manager.active_connections:
                await manager.broadcast({
                    "type": "heartbeat",
                    "message": "Server is alive",
                    "timestamp": datetime.utcnow().isoformat(),
                    "active_connections": len(manager.active_connections)
                })
    
    # Start the background task
    asyncio.create_task(simulate_updates())
