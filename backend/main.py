# main.py - Complete updated FastAPI backend with all fixes
from fastapi import FastAPI, Depends, HTTPException, status, Body, WebSocket, WebSocketDisconnect, Request, Form
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.middleware import Middleware
from pydantic import BaseModel
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
import asyncio
import json
import csv
import io
import pandas as pd
from slack_sdk import WebClient
import time
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import redis.asyncio as redis

# Database imports
from database import database, create_tables, initialize_default_data
from crud import (
    create_agent_data, get_latest_agent_data, get_all_agent_data,
    create_user, get_user_by_username, get_user_by_email, get_user_by_id,
    update_user_last_login, update_user_role, disable_user, enable_user,
    get_all_users, update_user_password, delete_user,
    create_alert_rule, get_alert_rules, get_alert_rule, update_alert_rule, 
    delete_alert_rule, toggle_alert_rule, create_incident, get_incidents,
    get_incident, update_incident_status, get_incident_stats, get_incidents_count,
    # Dashboard layouts CRUD functions
    get_user_dashboard_layouts, get_dashboard_layout,
    create_dashboard_layout, update_dashboard_layout, delete_dashboard_layout,
    set_default_layout, get_default_layout,
    verify_password,  # Add this import
    # New CRUD functions
    create_server, get_all_servers, get_server_by_id, get_server_by_hostname,
    update_server_last_seen, update_server, delete_server, get_agent_data_stats,
    log_user_activity, get_user_activities, get_user_activity_stats, get_suspicious_activities,
    log_visitor_request, get_visitor_logs, get_visitor_stats,
    # New AI and enhanced CRUD functions
    create_ai_insight, get_ai_insights, get_recent_ai_insights,
    create_server_location, get_server_locations, update_server_location,
    get_server_location_by_id, delete_server_location,
    create_user_preference, get_user_preference, update_user_preference,
    get_historical_metrics, get_metrics_trend,
    # Alert evaluation
    check_agent_data_for_alerts, evaluate_suspicious_processes
)

app = FastAPI(title="PurpleTeam Dashboard Backend with AI Insights")

# Enhanced CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# Manual CORS headers as backup
@app.middleware("http")
async def add_cors_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Access-Control-Allow-Origin"] = "http://localhost:5173"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, PATCH, DELETE, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "*"
    response.headers["Access-Control-Allow-Credentials"] = "true"
    return response

# Handle OPTIONS requests for CORS preflight
@app.options("/{rest_of_path:path}")
async def preflight_handler(request: Request, rest_of_path: str):
    response = JSONResponse(content={"message": "CORS preflight"})
    response.headers["Access-Control-Allow-Origin"] = "http://localhost:5173"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, PATCH, DELETE, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "*"
    return response

# Visitor logging middleware
@app.middleware("http")
async def log_visitor_middleware(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    processing_time = time.time() - start_time
    
    # Skip logging for certain paths to reduce noise
    skip_paths = ['/health', '/favicon.ico', '/static/', '/docs', '/redoc']
    if any(request.url.path.startswith(path) for path in skip_paths):
        return response
    
    try:
        # Get client IP
        if request.client:
            ip_address = request.client.host
        else:
            ip_address = "unknown"
        
        # Get user agent
        user_agent = request.headers.get('user-agent', '')
        
        # Get request body for suspicious detection (limit size to avoid memory issues)
        request_body = None
        if request.method in ['POST', 'PUT', 'PATCH']:
            content_type = request.headers.get('content-type', '')
            if 'application/json' in content_type or 'application/x-www-form-urlencoded' in content_type:
                try:
                    body = await request.body()
                    if len(body) < 10000:  # Limit to 10KB for logging
                        request_body = body.decode('utf-8', errors='ignore')
                except Exception:
                    pass
        
        # Log the visitor request
        await log_visitor_request(
            ip_address=ip_address,
            user_agent=user_agent,
            request_method=request.method,
            request_path=request.url.path,
            request_query=dict(request.query_params),
            request_headers=dict(request.headers),
            request_body=request_body,
            response_status=response.status_code,
            response_size=int(response.headers.get('content-length', 0)),
            processing_time=processing_time * 1000  # Convert to milliseconds
        )
    except Exception as e:
        print(f"Error in visitor logging middleware: {e}")
    
    return response

# Redis connection for caching
redis_client = None

async def get_redis():
    global redis_client
    if redis_client is None:
        redis_client = redis.Redis(host='localhost', port=6379, decode_responses=True)
    return redis_client

# Database connection events
@app.on_event("startup")
async def startup():
    await database.connect()
    await create_tables()
    await initialize_default_data()
    
    # Initialize Redis
    await get_redis()
    
    # Initialize alerting schema
    await init_alerting_schema()
    
    # Initialize AI services
    await init_ai_services()
    
    # Initialize default server locations
    await init_default_server_locations()
    
    # Create default admin user if it doesn't exist
    try:
        admin_user = await get_user_by_username("admin")
        if not admin_user:
            user_id = await create_user(
                username="admin",
                email="security@sesametechnologies.in",
                password="adminpass",
                role="admin"
            )
            if user_id:
                print("✅ Default admin user created")
            else:
                print("❌ Failed to create admin user")
        else:
            print("✅ Admin user already exists")
    except Exception as e:
        print(f"⚠️ Admin user creation skipped: {e}")
    
    print("✅ Database connected successfully!")

@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()
    if redis_client:
        await redis_client.close()
    print("✅ Database disconnected successfully!")

SECRET_KEY = "your-secret-key-change-in-production-12345"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Slack configuration
slack_token = "xoxb-your-slack-token-here"
client = WebClient(token=slack_token)

def send_slack_alert(message: str):
    try:
        # Temporarily disable Slack alerts to avoid errors
        print(f"📢 SECURITY ALERT: {message}")
        # client.chat_postMessage(channel="#alerts", text=message)
    except Exception as e:
        print(f"Alert logging: {e}")

# Using Argon2 for modern password hashing
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self.ai_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        print(f"New WebSocket connection. Total connections: {len(self.active_connections)}")

    async def connect_ai(self, websocket: WebSocket):
        await websocket.accept()
        self.ai_connections.append(websocket)
        print(f"New AI WebSocket connection. Total AI connections: {len(self.ai_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        if websocket in self.ai_connections:
            self.ai_connections.remove(websocket)
        print(f"WebSocket disconnected. Total connections: {len(self.active_connections)}, AI connections: {len(self.ai_connections)}")

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

    async def broadcast_ai(self, message: dict):
        if self.ai_connections:
            disconnected = []
            for connection in self.ai_connections:
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

# Server Models
class ServerBase(BaseModel):
    hostname: str
    ip_address: Optional[str] = None
    description: Optional[str] = None
    os_type: Optional[str] = "unknown"
    os_version: Optional[str] = None
    tags: Optional[List[str]] = []
    monitoring_enabled: Optional[bool] = True

class ServerCreate(ServerBase):
    pass

class Server(ServerBase):
    id: int
    created_at: Optional[datetime] = None
    last_seen: Optional[datetime] = None

    class Config:
        from_attributes = True

# Alerting Models
class AlertRuleBase(BaseModel):
    server_id: Optional[int] = None
    metric: str
    threshold_value: float
    comparison_operator: str
    severity: str = "medium"
    active: bool = True
    description: Optional[str] = None

class AlertRuleCreate(AlertRuleBase):
    pass

class AlertRule(AlertRuleBase):
    id: int
    created_by: Optional[int] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True

class IncidentBase(BaseModel):
    server_id: Optional[int] = None
    alert_rule_id: Optional[int] = None
    agent_data_id: Optional[int] = None
    incident_type: str
    message: str
    severity: str = "medium"
    metadata: Optional[Dict[str, Any]] = None

class IncidentCreate(IncidentBase):
    pass

class Incident(IncidentBase):
    id: int
    status: Optional[str] = "open"
    created_at: Optional[datetime] = None
    acknowledged_by: Optional[int] = None
    acknowledged_at: Optional[datetime] = None
    resolved_by: Optional[int] = None
    resolved_at: Optional[datetime] = None
    resolved_notes: Optional[str] = None

    class Config:
        from_attributes = True

class IncidentUpdate(BaseModel):
    status: Optional[str] = None
    resolved_notes: Optional[str] = None

class IncidentStats(BaseModel):
    status: Optional[str] = None
    count: int

# User Activity Models
class UserActivityBase(BaseModel):
    user_id: Optional[int] = None
    username: str
    activity_type: str
    ip_address: str
    user_agent: str
    success: bool = True
    details: Optional[Dict[str, Any]] = None

class UserActivity(UserActivityBase):
    id: int
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True

# Visitor Log Models
class VisitorLogBase(BaseModel):
    ip_address: str
    user_agent: str
    request_method: str
    request_path: str
    request_query: Optional[Dict[str, Any]] = None
    request_headers: Optional[Dict[str, Any]] = None
    request_body: Optional[str] = None
    response_status: int
    response_size: int
    processing_time: float
    suspicious: bool = False
    suspicious_reason: Optional[str] = None
    country: Optional[str] = None
    city: Optional[str] = None

class VisitorLog(VisitorLogBase):
    id: int
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True

# NEW MODELS FOR ENHANCED FEATURES

# AI Insights Models
class AIInsightBase(BaseModel):
    metric_type: str
    insight_type: str  # warning, info, success, critical
    message: str
    confidence: float
    action: Optional[str] = None
    server_id: Optional[int] = None

class AIInsightCreate(AIInsightBase):
    pass

class AIInsight(AIInsightBase):
    id: int
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True

# Server Location Models
class ServerLocationBase(BaseModel):
    name: str
    latitude: float
    longitude: float
    status: str = "online"
    current_load: float = 0.0
    active_users: int = 0
    server_id: Optional[int] = None

class ServerLocationCreate(ServerLocationBase):
    pass

class ServerLocation(ServerLocationBase):
    id: int
    last_updated: Optional[datetime] = None

    class Config:
        from_attributes = True

# User Preference Models
class UserPreferenceBase(BaseModel):
    dashboard_layout: str = "default"
    ai_assistant_enabled: bool = True
    notifications_email: bool = True
    notifications_push: bool = False
    theme: str = "dark"

class UserPreferenceCreate(UserPreferenceBase):
    user_id: int

class UserPreference(UserPreferenceBase):
    id: int
    user_id: int
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True

# Enhanced Agent Data Model
class EnhancedAgentData(BaseModel):
    cpu_usage: float
    memory_usage: float
    disk_usage: float
    network_activity: dict
    processes: list
    # New fields for AI analysis
    performance_score: Optional[float] = None
    anomaly_detected: Optional[bool] = False
    trend_analysis: Optional[dict] = None
    predicted_issues: Optional[list] = None
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    timestamp: Optional[datetime] = None

# AI Analysis Request/Response Models
class AIAnalysisRequest(BaseModel):
    metrics: List[Dict[str, Any]]
    server_id: Optional[int] = None
    analysis_type: str = "comprehensive"  # comprehensive, trend, anomaly

class AIAnalysisResponse(BaseModel):
    insights: List[AIInsight]
    predictions: Dict[str, Any]
    recommendations: List[str]
    confidence: float

# Authentication functions
def get_password_hash(password):
    return pwd_context.hash(password)

async def authenticate_user(username: str, password: str):
    print(f"🔐 Attempting authentication for: {username}")
    
    user = await get_user_by_username(username)
    if not user:
        # Also try email
        print(f"User {username} not found by username, trying email...")
        user = await get_user_by_email(username)
        if not user:
            print(f"❌ User {username} not found")
            return False
    
    user_dict = dict(user)
    print(f"✅ User found: {user_dict['username']} (role: {user_dict['role']})")
    
    # Verify password
    if not verify_password(password, user_dict["hashed_password"]):
        print(f"❌ Password verification failed for {username}")
        return False
    
    if user_dict.get("disabled"):
        print(f"❌ User {username} is disabled")
        return False
    
    # Update last login
    await update_user_last_login(user_dict["id"])
    print(f"✅ Authentication successful for {username}")
    
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
    if user_dict.get("disabled"):
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

# NEW AI ANALYSIS SERVICE
class AIAnalysisService:
    def __init__(self):
        self.anomaly_detector = None
        self.scaler = StandardScaler()
        self._initialize_models()
    
    def _initialize_models(self):
        """Initialize ML models for analysis"""
        try:
            # Simple isolation forest for anomaly detection
            self.anomaly_detector = IsolationForest(
                contamination=0.1,  # Expect 10% anomalies
                random_state=42
            )
            print("✅ AI models initialized successfully")
        except Exception as e:
            print(f"⚠️ AI model initialization error: {e}")
            self.anomaly_detector = None
    
    async def analyze_metrics_trend(self, historical_metrics: list) -> dict:
        """Analyze metric trends and predict issues"""
        analysis = {
            "trend": "stable",  # rising, falling, stable
            "predicted_peak": None,
            "anomalies": [],
            "recommendations": []
        }
        
        if len(historical_metrics) < 5:
            return analysis
        
        try:
            # Extract CPU usage for trend analysis
            cpu_values = [m.get('cpu_usage', 0) for m in historical_metrics if m.get('cpu_usage') is not None]
            
            if len(cpu_values) >= 5:
                recent_avg = sum(cpu_values[-5:]) / 5
                older_avg = sum(cpu_values[-10:-5]) / 5 if len(cpu_values) >= 10 else recent_avg
                
                if recent_avg > older_avg * 1.2:
                    analysis["trend"] = "rising"
                    analysis["recommendations"].append("CPU usage trending upward - consider optimization")
                elif recent_avg < older_avg * 0.8:
                    analysis["trend"] = "falling"
                    analysis["recommendations"].append("CPU usage decreasing - system may be underutilized")
                
                # Simple peak prediction based on time of day
                current_hour = datetime.utcnow().hour
                if 14 <= current_hour <= 16:  # 2-4 PM typically high
                    analysis["predicted_peak"] = {
                        "time": "2:30 PM",
                        "confidence": 0.85,
                        "expected_load": min(100, recent_avg * 1.3)
                    }
                
        except Exception as e:
            print(f"Trend analysis error: {e}")
        
        return analysis
    
    async def detect_anomalies(self, current_metrics: dict, historical_metrics: list) -> list:
        """Detect anomalies in current metrics"""
        anomalies = []
        
        try:
            if not historical_metrics or len(historical_metrics) < 10:
                return anomalies
            
            # Prepare features for anomaly detection
            features = []
            for metric in historical_metrics[-50:]:  # Use last 50 data points
                feature_vector = [
                    metric.get('cpu_usage', 0),
                    metric.get('memory_usage', 0),
                    metric.get('disk_usage', 0)
                ]
                features.append(feature_vector)
            
            # Add current metrics
            current_vector = [
                current_metrics.get('cpu_usage', 0),
                current_metrics.get('memory_usage', 0),
                current_metrics.get('disk_usage', 0)
            ]
            features.append(current_vector)
            
            # Fit and predict anomalies
            if self.anomaly_detector:
                predictions = self.anomaly_detector.fit_predict(features)
                is_anomaly = predictions[-1] == -1  # Last prediction is for current metrics
                
                if is_anomaly:
                    anomalies.append({
                        "type": "statistical_anomaly",
                        "metric": "system_metrics",
                        "confidence": 0.75,
                        "description": "Unusual pattern detected in system metrics"
                    })
            
        except Exception as e:
            print(f"Anomaly detection error: {e}")
        
        return anomalies
    
    async def generate_insights(self, current_metrics: dict, historical_data: list) -> list:
        """Generate AI-powered insights"""
        insights = []
        
        # CPU analysis
        cpu_usage = current_metrics.get('cpu_usage', 0)
        if cpu_usage > 90:
            insights.append({
                "metric_type": "cpu_usage",
                "insight_type": "critical",
                "message": "Critical CPU usage detected - system may become unresponsive",
                "confidence": 0.95,
                "action": "investigate_cpu_usage"
            })
        elif cpu_usage > 80:
            insights.append({
                "metric_type": "cpu_usage",
                "insight_type": "warning",
                "message": "High CPU usage detected",
                "confidence": 0.85,
                "action": "optimize_cpu"
            })
        elif cpu_usage < 10 and len(historical_data) > 10:
            # Check if this is a sudden drop
            recent_avg = sum([m.get('cpu_usage', 0) for m in historical_data[-5:]]) / 5
            if recent_avg > 30:  # Was recently higher
                insights.append({
                    "metric_type": "cpu_usage",
                    "insight_type": "warning",
                    "message": "Sudden drop in CPU usage - possible service failure",
                    "confidence": 0.70,
                    "action": "check_services"
                })
        
        # Memory analysis
        memory_usage = current_metrics.get('memory_usage', 0)
        if memory_usage > 95:
            insights.append({
                "metric_type": "memory_usage",
                "insight_type": "critical",
                "message": "Critical memory usage - system may crash",
                "confidence": 0.98,
                "action": "investigate_memory"
            })
        elif memory_usage > 85:
            insights.append({
                "metric_type": "memory_usage",
                "insight_type": "warning",
                "message": "High memory usage detected",
                "confidence": 0.88,
                "action": "optimize_memory"
            })
        
        # Disk analysis
        disk_usage = current_metrics.get('disk_usage', 0)
        if disk_usage > 95:
            insights.append({
                "metric_type": "disk_usage",
                "insight_type": "critical",
                "message": "Critical disk usage - system may become unstable",
                "confidence": 0.92,
                "action": "cleanup_disk"
            })
        elif disk_usage > 90:
            insights.append({
                "metric_type": "disk_usage",
                "insight_type": "warning",
                "message": "High disk usage detected",
                "confidence": 0.82,
                "action": "monitor_disk"
            })
        
        # Network analysis
        network_activity = current_metrics.get('network_activity', {})
        bytes_sent = network_activity.get('bytes_sent', 0)
        bytes_received = network_activity.get('bytes_received', 0)
        
        if bytes_sent > 100000000:  # 100 MB
            insights.append({
                "metric_type": "network",
                "insight_type": "info",
                "message": "High network throughput - monitor for unusual activity",
                "confidence": 0.75,
                "action": "monitor_network"
            })
        
        # Process analysis
        processes = current_metrics.get('processes', [])
        if len(processes) > 500:
            insights.append({
                "metric_type": "processes",
                "insight_type": "warning",
                "message": "High number of running processes",
                "confidence": 0.80,
                "action": "review_processes"
            })
        
        # Trend-based insights
        trend_analysis = await self.analyze_metrics_trend(historical_data)
        if trend_analysis["trend"] == "rising":
            insights.append({
                "metric_type": "trend",
                "insight_type": "info",
                "message": "System load trending upward",
                "confidence": 0.78,
                "action": "monitor_trend"
            })
        
        # Anomaly detection
        anomalies = await self.detect_anomalies(current_metrics, historical_data)
        for anomaly in anomalies:
            insights.append({
                "metric_type": anomaly["metric"],
                "insight_type": "warning",
                "message": anomaly["description"],
                "confidence": anomaly["confidence"],
                "action": "investigate_anomaly"
            })
        
        return insights

# NEW PREDICTION SERVICE
class PredictionService:
    async def predict_cpu_peak(self, historical_data: list) -> dict:
        """Predict next CPU usage peak"""
        if not historical_data:
            return {"peak_time": "No data available", "confidence": 0.0}
        
        try:
            # Simple prediction based on daily patterns
            hour = datetime.utcnow().hour
            if 14 <= hour <= 16:  # 2-4 PM typically high
                return {
                    "peak_time": "2:30 PM", 
                    "confidence": 0.85,
                    "expected_usage": min(100, self._calculate_expected_usage(historical_data, 1.3))
                }
            elif 10 <= hour <= 12:  # 10 AM-12 PM
                return {
                    "peak_time": "11:30 AM", 
                    "confidence": 0.72,
                    "expected_usage": min(100, self._calculate_expected_usage(historical_data, 1.2))
                }
            else:
                return {
                    "peak_time": "No significant peak predicted", 
                    "confidence": 0.45,
                    "expected_usage": self._calculate_expected_usage(historical_data, 1.0)
                }
        except Exception as e:
            print(f"CPU peak prediction error: {e}")
            return {"peak_time": "Prediction unavailable", "confidence": 0.0}
    
    def _calculate_expected_usage(self, historical_data: list, multiplier: float) -> float:
        """Calculate expected usage based on historical data"""
        if not historical_data:
            return 0.0
        
        recent_cpu = [m.get('cpu_usage', 0) for m in historical_data[-10:] if m.get('cpu_usage')]
        if not recent_cpu:
            return 0.0
        
        avg_usage = sum(recent_cpu) / len(recent_cpu)
        return min(100, avg_usage * multiplier)
    
    async def predict_memory_alert(self, current_usage: float, trend: str) -> str:
        """Predict when memory alert might occur"""
        if trend == "rising" and current_usage > 70:
            return "4 hours"
        elif trend == "stable" and current_usage > 80:
            return "8 hours"
        elif trend == "rising" and current_usage > 60:
            return "12 hours"
        else:
            return "No immediate alert predicted"
    
    async def predict_system_stability(self, metrics: dict, historical_data: list) -> dict:
        """Predict overall system stability"""
        stability_score = 100  # Start with perfect score
        
        # Deduct points based on various factors
        cpu_usage = metrics.get('cpu_usage', 0)
        if cpu_usage > 90:
            stability_score -= 40
        elif cpu_usage > 80:
            stability_score -= 20
        elif cpu_usage > 70:
            stability_score -= 10
        
        memory_usage = metrics.get('memory_usage', 0)
        if memory_usage > 95:
            stability_score -= 30
        elif memory_usage > 85:
            stability_score -= 15
        
        disk_usage = metrics.get('disk_usage', 0)
        if disk_usage > 95:
            stability_score -= 25
        elif disk_usage > 90:
            stability_score -= 10
        
        # Process count impact
        processes = metrics.get('processes', [])
        if len(processes) > 500:
            stability_score -= 10
        
        # Ensure score doesn't go below 0
        stability_score = max(0, stability_score)
        
        # Determine stability level
        if stability_score >= 80:
            level = "excellent"
        elif stability_score >= 60:
            level = "good"
        elif stability_score >= 40:
            level = "fair"
        elif stability_score >= 20:
            level = "poor"
        else:
            level = "critical"
        
        return {
            "score": stability_score,
            "level": level,
            "confidence": 0.85,
            "factors": {
                "cpu_impact": max(0, 100 - cpu_usage),
                "memory_impact": max(0, 100 - memory_usage),
                "disk_impact": max(0, 100 - disk_usage)
            }
        }

# Initialize AI services
ai_service = AIAnalysisService()
prediction_service = PredictionService()

async def init_ai_services():
    """Initialize AI services on startup"""
    print("✅ AI services initialized")

async def init_default_server_locations():
    """Initialize default server locations"""
    try:
        # Check if we already have server locations
        existing_locations = await get_server_locations()
        if existing_locations:
            print("✅ Server locations already initialized")
            return
        
        # Default server locations for global map
        default_locations = [
            {
                "name": "US East",
                "latitude": 40.7128,
                "longitude": -74.0060,
                "status": "online",
                "current_load": 45.0,
                "active_users": 1245,
                "server_id": None
            },
            {
                "name": "US West", 
                "latitude": 34.0522,
                "longitude": -118.2437,
                "status": "online",
                "current_load": 32.0,
                "active_users": 876,
                "server_id": None
            },
            {
                "name": "Europe",
                "latitude": 51.5074,
                "longitude": -0.1278,
                "status": "online", 
                "current_load": 28.0,
                "active_users": 654,
                "server_id": None
            },
            {
                "name": "Asia Pacific",
                "latitude": 35.6762,
                "longitude": 139.6503,
                "status": "online",
                "current_load": 51.0,
                "active_users": 1987,
                "server_id": None
            },
            {
                "name": "South America",
                "latitude": -23.5505,
                "longitude": -46.6333,
                "status": "online",
                "current_load": 19.0,
                "active_users": 432,
                "server_id": None
            }
        ]
        
        for location_data in default_locations:
            await create_server_location(location_data)
        
        print("✅ Default server locations initialized")
        
    except Exception as e:
        print(f"⚠️ Server locations initialization error: {e}")

# Alerting Schema Initialization
async def init_alerting_schema():
    """Initialize the alerting schema with default rules - SQLite compatible"""
    try:
        # Insert default alert rules if they don't exist
        default_rules = [
            {
                "metric": "cpu_usage",
                "threshold_value": 90.0,
                "comparison_operator": ">",
                "severity": "high",
                "description": "CPU usage exceeds 90%"
            },
            {
                "metric": "memory_usage", 
                "threshold_value": 85.0,
                "comparison_operator": ">",
                "severity": "high",
                "description": "Memory usage exceeds 85%"
            },
            {
                "metric": "disk_usage",
                "threshold_value": 90.0,
                "comparison_operator": ">", 
                "severity": "critical",
                "description": "Disk usage exceeds 90%"
            },
            {
                "metric": "cpu_usage",
                "threshold_value": 80.0,
                "comparison_operator": ">",
                "severity": "medium", 
                "description": "CPU usage exceeds 80%"
            },
            {
                "metric": "memory_usage",
                "threshold_value": 75.0,
                "comparison_operator": ">",
                "severity": "medium",
                "description": "Memory usage exceeds 75%"
            }
        ]
        
        for rule in default_rules:
            existing = await database.fetch_one(
                "SELECT id FROM alert_rules WHERE metric = :metric AND threshold_value = :threshold_value AND comparison_operator = :comparison_operator",
                {
                    "metric": rule["metric"],
                    "threshold_value": rule["threshold_value"],
                    "comparison_operator": rule["comparison_operator"]
                }
            )
            if not existing:
                await database.execute("""
                    INSERT INTO alert_rules (metric, threshold_value, comparison_operator, severity, description, created_at, updated_at)
                    VALUES (:metric, :threshold_value, :comparison_operator, :severity, :description, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                """, rule)
                print(f"✅ Created default alert rule: {rule['metric']} {rule['comparison_operator']} {rule['threshold_value']}")
        
        print("✅ Alerting schema initialized successfully!")
        
    except Exception as e:
        print(f"⚠️ Alerting schema initialization error: {e}")

# DEBUGGING ENDPOINTS - REMOVE IN PRODUCTION
@app.get("/debug/users")
async def debug_users():
    """Check all users in database"""
    try:
        users = await database.fetch_all("SELECT id, username, email, role, disabled, hashed_password FROM users")
        users_list = []
        for user in users:
            user_dict = dict(user)
            # Don't show the full hashed password for security
            if 'hashed_password' in user_dict:
                user_dict['hashed_password'] = user_dict['hashed_password'][:20] + "..." if user_dict['hashed_password'] else "None"
            users_list.append(user_dict)
        return {"users": users_list}
    except Exception as e:
        return {"error": str(e)}

@app.post("/debug/create-admin")
async def debug_create_admin():
    """Create admin user with proper debugging"""
    try:
        # Check if admin already exists
        existing_admin = await database.fetch_one(
            "SELECT * FROM users WHERE username = 'admin'"
        )
        
        if existing_admin:
            admin_dict = dict(existing_admin)
            return {
                "message": "Admin user already exists",
                "admin": {
                    "id": admin_dict["id"],
                    "username": admin_dict["username"],
                    "role": admin_dict["role"],
                    "disabled": admin_dict["disabled"]
                }
            }
        
        # Create new admin
        hashed_password = get_password_hash("adminpass")
        user_id = await database.execute(
            """
            INSERT INTO users (username, email, hashed_password, role, disabled, created_at)
            VALUES (:username, :email, :hashed_password, :role, :disabled, :created_at)
            """,
            {
                "username": "admin",
                "email": "security@sesametechnologies.in", 
                "hashed_password": hashed_password,
                "role": "admin",
                "disabled": False,
                "created_at": datetime.utcnow()
            }
        )
        
        return {
            "message": "Admin user created successfully",
            "user_id": user_id,
            "username": "admin",
            "password": "adminpass"
        }
    except Exception as e:
        return {"error": str(e)}

@app.post("/debug/test-auth")
async def debug_test_auth(username: str = Form("admin"), password: str = Form("adminpass")):
    """Test authentication directly"""
    try:
        user = await authenticate_user(username, password)
        if user:
            access_token = create_access_token(
                data={"sub": user.username},
                expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
            )
            return {
                "success": True,
                "message": "Authentication successful",
                "user": {
                    "username": user.username,
                    "role": user.role
                },
                "access_token": access_token
            }
        else:
            return {
                "success": False,
                "message": "Authentication failed"
            }
    except Exception as e:
        return {
            "success": False,
            "message": f"Error: {str(e)}"
        }

@app.post("/debug/reset-admin-password")
async def debug_reset_admin_password():
    """Reset admin password to 'adminpass'"""
    try:
        # Check if admin exists
        admin_user = await get_user_by_username("admin")
        if not admin_user:
            return {"success": False, "message": "Admin user not found"}
        
        # Update password
        hashed_password = get_password_hash("adminpass")
        await database.execute(
            "UPDATE users SET hashed_password = :hashed_password WHERE username = 'admin'",
            {"hashed_password": hashed_password}
        )
        
        return {
            "success": True,
            "message": "Admin password reset to 'adminpass'"
        }
    except Exception as e:
        return {"success": False, "message": f"Error: {str(e)}"}

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
    
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create user"
        )
    
    # Create default user preferences
    await create_user_preference(user_id, {
        "preference_type": "general",
        "preference_value": {
            "dashboard_layout": "default",
            "ai_assistant_enabled": True,
            "notifications_email": True,
            "notifications_push": False,
            "theme": "dark"
        }
    })
    
    # Get the created user
    user = await get_user_by_id(user_id)
    return User(**dict(user))

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    print(f"🔐 Login attempt for username: {form_data.username}")
    
    user = await authenticate_user(form_data.username, form_data.password)
    if not user:
        # Log failed login attempt
        await log_user_activity(
            username=form_data.username,
            activity_type="login",
            ip_address="unknown",  # In production, get from request
            user_agent="unknown",
            success=False,
            details={"reason": "invalid_credentials"}
        )
        
        send_slack_alert(f"🚨 Failed login attempt for username: {form_data.username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    # Log successful login
    await log_user_activity(
        user_id=user.id,
        username=user.username,
        activity_type="login",
        ip_address="unknown",  # In production, get from request
        user_agent="unknown", 
        success=True,
        details={"role": user.role}
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

# Enhanced user profile with preferences
@app.get("/users/me/enhanced")
async def get_enhanced_user_profile(current_user: User = Depends(get_current_active_user)):
    """Get enhanced user profile with preferences"""
    preferences = await get_user_preference(current_user.id)
    
    user_prefs = {
        "dashboard_layout": "default",
        "ai_assistant_enabled": True,
        "notifications_email": True,
        "notifications_push": False,
        "theme": "dark"
    }
    
    if preferences:
        prefs_dict = dict(preferences)
        preference_value = prefs_dict.get('preference_value', {})
        if isinstance(preference_value, dict):
            user_prefs.update({
                "dashboard_layout": preference_value.get("dashboard_layout", "default"),
                "ai_assistant_enabled": preference_value.get("ai_assistant_enabled", True),
                "notifications_email": preference_value.get("notifications_email", True),
                "notifications_push": preference_value.get("notifications_push", False),
                "theme": preference_value.get("theme", "dark")
            })
    
    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "role": current_user.role,
        "preferences": user_prefs,
        "created_at": current_user.created_at
    }

# Update user preferences
@app.put("/users/me/preferences")
async def update_user_preferences(
    preferences: UserPreferenceBase,
    current_user: User = Depends(get_current_active_user)
):
    """Update user preferences"""
    preference_data = {
        "preference_type": "general",
        "preference_value": preferences.dict()
    }
    
    result = await update_user_preference(current_user.id, preference_data)
    if not result:
        # Create if doesn't exist
        preference_data["user_id"] = current_user.id
        await create_user_preference(current_user.id, preference_data)
    
    return {"message": "Preferences updated successfully"}

# Password change endpoint
@app.put("/users/me/password")
async def change_password(
    password_data: PasswordChange,
    current_user: User = Depends(get_current_active_user)
):
    """
    Change current user's password
    """
    # Get user from database
    user_db = await get_user_by_username(current_user.username)
    user_dict = dict(user_db)
    
    # Verify current password
    if not verify_password(password_data.current_password, user_dict["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect"
        )
    
    # Update password
    success = await update_user_password(current_user.id, password_data.new_password)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update password"
        )
    
    # Log password change activity
    await log_user_activity(
        user_id=current_user.id,
        username=current_user.username,
        activity_type="password_change",
        ip_address="unknown",
        user_agent="unknown",
        success=True
    )
    
    return {"message": "Password updated successfully"}

# Admin-only routes
@app.get("/admin/users", response_model=List[User])
async def get_all_users_admin(current_user: User = Depends(get_admin_user)):
    """
    Get all users (Admin only) - Only active users
    """
    users_data = await get_all_users()
    # Filter out disabled users
    active_users = [user for user in users_data if not user.get("disabled", False)]
    return [User(**dict(user)) for user in active_users]

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
    
    success = await update_user_role(user_id, new_role, current_user.id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update user role"
        )
    
    return {"message": f"User role updated to {new_role}"}

@app.put("/admin/users/{user_id}/disable")
async def disable_user_admin(user_id: int, current_user: User = Depends(get_admin_user)):
    """
    Disable a user (Admin only)
    """
    success = await disable_user(user_id, current_user.id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to disable user"
        )
    
    return {"message": "User disabled"}

@app.put("/admin/users/{user_id}/enable")
async def enable_user_admin(user_id: int, current_user: User = Depends(get_admin_user)):
    """
    Enable a user (Admin only)
    """
    success = await enable_user(user_id, current_user.id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to enable user"
        )
    
    return {"message": "User enabled"}

@app.delete("/admin/users/{user_id}")
async def delete_user_admin(user_id: int, current_user: User = Depends(get_admin_user)):
    """
    Delete a user (Admin only)
    """
    # Prevent admin from deleting themselves
    if user_id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete your own account"
        )
    
    # Get user to ensure they exist
    user_to_delete = await get_user_by_id(user_id)
    if not user_to_delete:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Actually delete the user from database
    success = await delete_user(user_id, current_user.id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete user"
        )
    
    return {"message": "User deleted successfully"}

# ==================== NEW AI INSIGHTS ENDPOINTS ====================

@app.get("/api/ai/insights")
async def get_ai_insights_endpoint(
    server_id: Optional[int] = None,
    insight_type: Optional[str] = None,
    limit: int = 50,
    current_user: User = Depends(get_current_active_user)
):
    """Get AI-powered system insights and predictions"""
    try:
        insights = await get_ai_insights(
            server_id=server_id,
            insight_type=insight_type,
            limit=limit
        )
        
        insights_list = []
        for insight in insights:
            insight_dict = dict(insight)
            insights_list.append(AIInsight(**insight_dict))
        
        return {
            "insights": insights_list,
            "total": len(insights_list),
            "generated_at": datetime.utcnow().isoformat() + 'Z'
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI insights error: {str(e)}")

@app.post("/api/ai/analyze-metrics")
async def analyze_metrics_endpoint(
    analysis_request: AIAnalysisRequest,
    current_user: User = Depends(get_current_active_user)
):
    """Analyze metrics and provide AI recommendations"""
    try:
        # Get historical data for context
        historical_data = await get_historical_metrics(
            server_id=analysis_request.server_id,
            limit=100
        )
        
        # Generate insights using AI service
        insights_data = await ai_service.generate_insights(
            analysis_request.metrics[-1] if analysis_request.metrics else {},
            historical_data
        )
        
        # Generate predictions
        predictions = await prediction_service.predict_system_stability(
            analysis_request.metrics[-1] if analysis_request.metrics else {},
            historical_data
        )
        
        # Store insights in database
        stored_insights = []
        for insight in insights_data:
            insight_id = await create_ai_insight({
                "metric_type": insight["metric_type"],
                "insight_type": insight["insight_type"],
                "message": insight["message"],
                "confidence": insight["confidence"],
                "action": insight.get("action"),
                "server_id": analysis_request.server_id
            })
            
            if insight_id:
                stored_insight_data = await get_ai_insights(insight_id=insight_id)
                if stored_insight_data:
                    stored_insights.append(AIInsight(**dict(stored_insight_data[0])))
        
        # Broadcast AI insights via WebSocket
        await manager.broadcast_ai({
            "type": "ai_insights",
            "insights": insights_data,
            "predictions": predictions,
            "server_id": analysis_request.server_id,
            "timestamp": datetime.utcnow().isoformat() + 'Z'
        })
        
        return AIAnalysisResponse(
            insights=stored_insights,
            predictions=predictions,
            recommendations=[insight["message"] for insight in insights_data],
            confidence=sum(insight["confidence"] for insight in insights_data) / len(insights_data) if insights_data else 0.0
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Metrics analysis error: {str(e)}")

@app.get("/api/ai/predictions")
async def get_system_predictions_endpoint(
    server_id: Optional[int] = None,
    current_user: User = Depends(get_current_active_user)
):
    """Get system performance predictions"""
    try:
        # Get recent metrics for prediction
        historical_data = await get_historical_metrics(
            server_id=server_id,
            limit=50
        )
        
        if not historical_data:
            return {
                "predictions": {
                    "cpu_peak": {"peak_time": "No data available", "confidence": 0.0},
                    "memory_alert": "No data available",
                    "system_stability": {"score": 0, "level": "unknown", "confidence": 0.0}
                },
                "timestamp": datetime.utcnow().isoformat() + 'Z'
            }
        
        # Get current metrics
        current_metrics = historical_data[-1] if historical_data else {}
        
        # Generate predictions
        cpu_peak_prediction = await prediction_service.predict_cpu_peak(historical_data)
        
        trend_analysis = await ai_service.analyze_metrics_trend(historical_data)
        memory_alert_prediction = await prediction_service.predict_memory_alert(
            current_metrics.get('memory_usage', 0),
            trend_analysis["trend"]
        )
        
        stability_prediction = await prediction_service.predict_system_stability(
            current_metrics,
            historical_data
        )
        
        predictions = {
            "cpu_peak": cpu_peak_prediction,
            "memory_alert": memory_alert_prediction,
            "system_stability": stability_prediction,
            "trend_analysis": trend_analysis
        }
        
        return {
            "predictions": predictions,
            "timestamp": datetime.utcnow().isoformat() + 'Z'
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Prediction error: {str(e)}")

# ==================== GLOBAL SERVER MAP ENDPOINTS ====================

@app.get("/api/servers/geolocation")
async def get_server_geolocations_endpoint(current_user: User = Depends(get_current_active_user)):
    """Get server locations for world map"""
    try:
        server_locations = await get_server_locations()
        
        locations_list = []
        for location in server_locations:
            location_dict = dict(location)
            locations_list.append(ServerLocation(**location_dict))
        
        return locations_list
        
    except Exception as e:
        # Fallback to default locations if database error
        return [
            {
                "id": 1,
                "name": "US East",
                "latitude": 40.7128,
                "longitude": -74.0060,
                "status": "online",
                "current_load": 45.0,
                "active_users": 1245,
                "server_id": None,
                "last_updated": datetime.utcnow().isoformat() + 'Z'
            },
            {
                "id": 2,
                "name": "US West",
                "latitude": 34.0522,
                "longitude": -118.2437,
                "status": "online",
                "current_load": 32.0,
                "active_users": 876,
                "server_id": None,
                "last_updated": datetime.utcnow().isoformat() + 'Z'
            },
            {
                "id": 3,
                "name": "Europe",
                "latitude": 51.5074,
                "longitude": -0.1278,
                "status": "online",
                "current_load": 28.0,
                "active_users": 654,
                "server_id": None,
                "last_updated": datetime.utcnow().isoformat() + 'Z'
            },
            {
                "id": 4,
                "name": "Asia Pacific",
                "latitude": 35.6762,
                "longitude": 139.6503,
                "status": "online",
                "current_load": 51.0,
                "active_users": 1987,
                "server_id": None,
                "last_updated": datetime.utcnow().isoformat() + 'Z'
            },
            {
                "id": 5,
                "name": "South America",
                "latitude": -23.5505,
                "longitude": -46.6333,
                "status": "online",
                "current_load": 19.0,
                "active_users": 432,
                "server_id": None,
                "last_updated": datetime.utcnow().isoformat() + 'Z'
            }
        ]

@app.post("/api/servers/geolocation")
async def create_server_location_endpoint(
    location_data: ServerLocationCreate,
    current_user: User = Depends(get_admin_user)
):
    """Create a new server location (Admin only)"""
    try:
        location_id = await create_server_location(location_data.dict())
        if not location_id:
            raise HTTPException(status_code=500, detail="Failed to create server location")
        
        location = await get_server_location_by_id(location_id)
        return ServerLocation(**dict(location))
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Server location creation error: {str(e)}")

@app.put("/api/servers/geolocation/{location_id}")
async def update_server_location_endpoint(
    location_id: int,
    location_data: ServerLocationCreate,
    current_user: User = Depends(get_admin_user)
):
    """Update server location (Admin only)"""
    try:
        location = await update_server_location(location_id, location_data.dict())
        if not location:
            raise HTTPException(status_code=404, detail="Server location not found")
        
        return ServerLocation(**dict(location))
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Server location update error: {str(e)}")

@app.delete("/api/servers/geolocation/{location_id}")
async def delete_server_location_endpoint(
    location_id: int,
    current_user: User = Depends(get_admin_user)
):
    """Delete server location (Admin only)"""
    try:
        success = await delete_server_location(location_id)
        if not success:
            raise HTTPException(status_code=404, detail="Server location not found")
        
        return {"message": "Server location deleted successfully"}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Server location deletion error: {str(e)}")

# ==================== ADAPTIVE DASHBOARD ENDPOINTS ====================

@app.get("/api/dashboard/layouts/adaptive")
async def get_adaptive_layout_endpoint(
    server_id: Optional[int] = None,
    metrics_type: str = "overview",
    current_user: User = Depends(get_current_active_user)
):
    """Get adaptive dashboard layout based on current metrics and user preferences"""
    try:
        # Get user preferences
        preferences = await get_user_preference(current_user.id)
        user_prefs = preferences.get('preference_value', {}) if preferences else {}
        
        # Get recent metrics for context
        historical_data = await get_historical_metrics(server_id=server_id, limit=10)
        
        # Determine optimal layout based on metrics and preferences
        layout_config = await generate_adaptive_layout(
            historical_data, 
            user_prefs, 
            metrics_type
        )
        
        return {
            "layout": layout_config,
            "preferences": user_prefs,
            "context": {
                "server_id": server_id,
                "metrics_type": metrics_type,
                "data_points": len(historical_data)
            },
            "generated_at": datetime.utcnow().isoformat() + 'Z'
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Adaptive layout error: {str(e)}")

@app.post("/api/dashboard/layouts/save")
async def save_dashboard_layout_endpoint(
    layout_data: dict = Body(...),
    current_user: User = Depends(get_current_active_user)
):
    """Save user's dashboard layout preferences"""
    try:
        layout_name = layout_data.get("name", "Custom Layout")
        layout_config = layout_data.get("layout", {})
        widgets = layout_data.get("widgets", {})
        filters = layout_data.get("filters", {})
        is_default = layout_data.get("is_default", False)
        
        # Create or update dashboard layout
        layout_id = await create_dashboard_layout(
            user_id=current_user.id,
            name=layout_name,
            layout=layout_config,
            widgets=widgets,
            filters=filters,
            is_default=is_default
        )
        
        if not layout_id:
            raise HTTPException(status_code=500, detail="Failed to save dashboard layout")
        
        return {
            "message": "Dashboard layout saved successfully",
            "layout_id": layout_id,
            "is_default": is_default
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Layout save error: {str(e)}")

async def generate_adaptive_layout(historical_data: list, user_prefs: dict, metrics_type: str) -> dict:
    """Generate adaptive dashboard layout based on metrics and preferences"""
    
    # Base layout configuration
    base_layout = {
        "grid": {
            "columns": 12,
            "rowHeight": 30,
            "breakpoints": {"lg": 1200, "md": 996, "sm": 768, "xs": 480, "xxs": 0},
            "layouts": {
                "lg": [],
                "md": [],
                "sm": [],
                "xs": [],
                "xxs": []
            }
        },
        "widgets": {}
    }
    
    # Determine layout based on metrics type
    if metrics_type == "overview":
        base_layout["grid"]["layouts"]["lg"] = [
            {"i": "cpu-usage", "x": 0, "y": 0, "w": 4, "h": 3},
            {"i": "memory-usage", "x": 4, "y": 0, "w": 4, "h": 3},
            {"i": "disk-usage", "x": 8, "y": 0, "w": 4, "h": 3},
            {"i": "network-activity", "x": 0, "y": 3, "w": 6, "h": 3},
            {"i": "process-monitor", "x": 6, "y": 3, "w": 6, "h": 3},
            {"i": "ai-insights", "x": 0, "y": 6, "w": 12, "h": 4}
        ]
    elif metrics_type == "performance":
        base_layout["grid"]["layouts"]["lg"] = [
            {"i": "performance-metrics", "x": 0, "y": 0, "w": 8, "h": 4},
            {"i": "system-predictions", "x": 8, "y": 0, "w": 4, "h": 4},
            {"i": "trend-analysis", "x": 0, "y": 4, "w": 6, "h": 4},
            {"i": "anomaly-detection", "x": 6, "y": 4, "w": 6, "h": 4}
        ]
    elif metrics_type == "security":
        base_layout["grid"]["layouts"]["lg"] = [
            {"i": "security-alerts", "x": 0, "y": 0, "w": 6, "h": 4},
            {"i": "user-activities", "x": 6, "y": 0, "w": 6, "h": 4},
            {"i": "incident-monitor", "x": 0, "y": 4, "w": 12, "h": 4},
            {"i": "threat-prediction", "x": 0, "y": 8, "w": 12, "h": 3}
        ]
    else:  # Default layout
        base_layout["grid"]["layouts"]["lg"] = [
            {"i": "system-overview", "x": 0, "y": 0, "w": 12, "h": 2},
            {"i": "metric-charts", "x": 0, "y": 2, "w": 8, "h": 4},
            {"i": "ai-recommendations", "x": 8, "y": 2, "w": 4, "h": 4},
            {"i": "recent-events", "x": 0, "y": 6, "w": 12, "h": 3}
        ]
    
    # Apply user preferences
    if user_prefs:
        theme = user_prefs.get("theme", "dark")
        base_layout["theme"] = theme
        
        if not user_prefs.get("ai_assistant_enabled", True):
            # Remove AI-related widgets if disabled
            base_layout["grid"]["layouts"]["lg"] = [
                widget for widget in base_layout["grid"]["layouts"]["lg"] 
                if "ai" not in widget["i"] and "prediction" not in widget["i"]
            ]
    
    return base_layout

# ==================== SERVER MANAGEMENT ENDPOINTS ====================

@app.get("/servers", response_model=List[Server])
async def get_all_servers_endpoint(current_user: User = Depends(get_current_active_user)):
    """Get all servers"""
    servers_data = await get_all_servers()
    servers_list = []
    for server in servers_data:
        server_dict = dict(server)
        if server_dict.get('tags') and isinstance(server_dict['tags'], str):
            try:
                server_dict['tags'] = json.loads(server_dict['tags'])
            except json.JSONDecodeError:
                server_dict['tags'] = []
        servers_list.append(Server(**server_dict))
    return servers_list

@app.get("/servers/{server_id}", response_model=Server)
async def get_server_by_id_endpoint(server_id: int, current_user: User = Depends(get_current_active_user)):
    """Get server by ID"""
    server = await get_server_by_id(server_id)
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")
    
    server_dict = dict(server)
    if server_dict.get('tags') and isinstance(server_dict['tags'], str):
        try:
            server_dict['tags'] = json.loads(server_dict['tags'])
        except json.JSONDecodeError:
            server_dict['tags'] = []
    
    return Server(**server_dict)

@app.post("/servers", response_model=Server)
async def create_server_endpoint(
    server_data: ServerCreate,
    current_user: User = Depends(get_admin_user)
):
    """Create a new server (Admin only)"""
    server_id = await create_server(server_data.dict(), current_user.id)
    if not server_id:
        raise HTTPException(status_code=500, detail="Failed to create server")
    
    server = await get_server_by_id(server_id)
    server_dict = dict(server)
    if server_dict.get('tags') and isinstance(server_dict['tags'], str):
        try:
            server_dict['tags'] = json.loads(server_dict['tags'])
        except json.JSONDecodeError:
            server_dict['tags'] = []
    
    return Server(**server_dict)

@app.put("/servers/{server_id}", response_model=Server)
async def update_server_endpoint(
    server_id: int,
    server_data: ServerCreate,
    current_user: User = Depends(get_admin_user)
):
    """Update server information (Admin only)"""
    server = await update_server(server_id, server_data.dict(), current_user.id)
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")
    
    server_dict = dict(server)
    if server_dict.get('tags') and isinstance(server_dict['tags'], str):
        try:
            server_dict['tags'] = json.loads(server_dict['tags'])
        except json.JSONDecodeError:
            server_dict['tags'] = []
    
    return Server(**server_dict)

@app.delete("/servers/{server_id}")
async def delete_server_endpoint(server_id: int, current_user: User = Depends(get_admin_user)):
    """Delete a server (Admin only)"""
    server = await get_server_by_id(server_id)
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")
    
    success = await delete_server(server_id, current_user.id)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to delete server")
    
    return {"message": "Server deleted successfully"}

@app.get("/servers/{server_id}/stats")
async def get_server_stats_endpoint(server_id: int, current_user: User = Depends(get_current_active_user)):
    """Get server statistics"""
    server = await get_server_by_id(server_id)
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")
    
    stats = await get_agent_data_stats(server_id)
    incidents = await get_incidents_count(server_id=server_id)
    recent_incidents = await get_incidents(server_id=server_id, limit=10)
    
    # Get AI insights for this server
    ai_insights = await get_ai_insights(server_id=server_id, limit=5)
    
    return {
        "server": server,
        "data_stats": dict(stats) if stats else {},
        "incident_count": incidents,
        "recent_incidents": len(recent_incidents),
        "ai_insights": [dict(insight) for insight in ai_insights]
    }

# ==================== USER ACTIVITY ENDPOINTS ====================

@app.get("/admin/user-activities", response_model=List[UserActivity])
async def get_user_activities_endpoint(
    user_id: Optional[int] = None,
    username: Optional[str] = None,
    activity_type: Optional[str] = None,
    ip_address: Optional[str] = None,
    success: Optional[bool] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    current_user: User = Depends(get_admin_user)
):
    """Get user activities (Admin only)"""
    activities = await get_user_activities(
        user_id=user_id,
        username=username,
        activity_type=activity_type,
        ip_address=ip_address,
        success=success,
        start_date=start_date,
        end_date=end_date,
        limit=limit,
        offset=offset
    )
    
    activities_list = []
    for activity in activities:
        activity_dict = dict(activity)
        if activity_dict.get('details') and isinstance(activity_dict['details'], str):
            try:
                activity_dict['details'] = json.loads(activity_dict['details'])
            except json.JSONDecodeError:
                activity_dict['details'] = {}
        activities_list.append(UserActivity(**activity_dict))
    
    return activities_list

@app.get("/admin/user-activities/stats")
async def get_user_activity_stats_endpoint(
    days: int = 30,
    current_user: User = Depends(get_admin_user)
):
    """Get user activity statistics (Admin only)"""
    stats = await get_user_activity_stats(days=days)
    suspicious = await get_suspicious_activities()
    
    return {
        "activity_stats": [dict(stat) for stat in stats],
        "suspicious_activities": [dict(activity) for activity in suspicious]
    }

# ==================== VISITOR LOGS ENDPOINTS ====================

@app.get("/admin/visitor-logs", response_model=List[VisitorLog])
async def get_visitor_logs_endpoint(
    ip_address: Optional[str] = None,
    request_method: Optional[str] = None,
    request_path: Optional[str] = None,
    suspicious: Optional[bool] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    current_user: User = Depends(get_admin_user)
):
    """Get visitor logs (Admin only)"""
    logs = await get_visitor_logs(
        ip_address=ip_address,
        request_method=request_method,
        request_path=request_path,
        suspicious=suspicious,
        start_date=start_date,
        end_date=end_date,
        limit=limit,
        offset=offset
    )
    
    logs_list = []
    for log in logs:
        log_dict = dict(log)
        for field in ['request_query', 'request_headers']:
            if log_dict.get(field) and isinstance(log_dict[field], str):
                try:
                    log_dict[field] = json.loads(log_dict[field])
                except json.JSONDecodeError:
                    log_dict[field] = {}
        logs_list.append(VisitorLog(**log_dict))
    
    return logs_list

@app.get("/admin/visitor-logs/stats")
async def get_visitor_stats_endpoint(
    days: int = 7,
    current_user: User = Depends(get_admin_user)
):
    """Get visitor statistics (Admin only)"""
    stats = await get_visitor_stats(days=days)
    
    return {
        "total_requests": stats["total_requests"],
        "suspicious_requests": stats["suspicious_requests"],
        "top_ips": [dict(ip) for ip in stats["top_ips"]],
        "requests_by_method": [dict(method) for method in stats["requests_by_method"]],
        "requests_by_status": [dict(status) for status in stats["requests_by_status"]]
    }

# ==================== ALERT RULES MANAGEMENT ====================

@app.get("/alerts/rules", response_model=List[AlertRule])
async def get_alert_rules_endpoint(
    active_only: bool = True,
    server_id: Optional[int] = None,
    current_user: User = Depends(get_current_active_user)
):
    """Get all alert rules"""
    rules = await get_alert_rules(active_only=active_only, server_id=server_id)
    alert_rules = []
    for rule in rules:
        rule_dict = dict(rule)
        if not rule_dict.get('created_at'):
            rule_dict['created_at'] = datetime.utcnow()
        if not rule_dict.get('updated_at'):
            rule_dict['updated_at'] = datetime.utcnow()
        alert_rules.append(AlertRule(**rule_dict))
    return alert_rules

@app.post("/alerts/rules", response_model=AlertRule)
async def create_alert_rule_endpoint(
    alert_rule: AlertRuleCreate,
    current_user: User = Depends(get_current_active_user)
):
    """Create a new alert rule"""
    rule = await create_alert_rule(alert_rule.dict(), current_user.id)
    if not rule:
        raise HTTPException(status_code=500, detail="Failed to create alert rule")
    
    rule_dict = dict(rule)
    if not rule_dict.get('created_at'):
        rule_dict['created_at'] = datetime.utcnow()
    if not rule_dict.get('updated_at'):
        rule_dict['updated_at'] = datetime.utcnow()
    
    return AlertRule(**rule_dict)

@app.put("/alerts/rules/{rule_id}", response_model=AlertRule)
async def update_alert_rule_endpoint(
    rule_id: int,
    alert_rule: AlertRuleCreate,
    current_user: User = Depends(get_current_active_user)
):
    """Update an alert rule"""
    rule = await update_alert_rule(rule_id, alert_rule.dict())
    if not rule:
        raise HTTPException(status_code=404, detail="Alert rule not found")
    
    rule_dict = dict(rule)
    if not rule_dict.get('updated_at'):
        rule_dict['updated_at'] = datetime.utcnow()
    
    return AlertRule(**rule_dict)

@app.delete("/alerts/rules/{rule_id}")
async def delete_alert_rule_endpoint(
    rule_id: int,
    current_user: User = Depends(get_current_active_user)
):
    """Delete an alert rule"""
    success = await delete_alert_rule(rule_id)
    if not success:
        raise HTTPException(status_code=404, detail="Alert rule not found")
    return {"message": "Alert rule deleted successfully"}

@app.patch("/alerts/rules/{rule_id}/toggle")
async def toggle_alert_rule_endpoint(
    rule_id: int,
    active: bool,
    current_user: User = Depends(get_current_active_user)
):
    """Toggle alert rule active status"""
    rule = await toggle_alert_rule(rule_id, active)
    if not rule:
        raise HTTPException(status_code=404, detail="Alert rule not found")
    
    rule_dict = dict(rule)
    if not rule_dict.get('updated_at'):
        rule_dict['updated_at'] = datetime.utcnow()
    
    return AlertRule(**rule_dict)

# ==================== INCIDENTS MANAGEMENT ====================

@app.get("/incidents", response_model=List[Incident])
async def get_incidents_endpoint(
    status: str = None,
    severity: str = None,
    server_id: Optional[int] = None,
    limit: int = 100,
    offset: int = 0,
    current_user: User = Depends(get_current_active_user)
):
    """Get incidents with optional filtering"""
    incidents = await get_incidents(
        status=status, 
        severity=severity, 
        server_id=server_id,
        limit=limit, 
        offset=offset
    )
    incident_list = []
    for incident in incidents:
        incident_dict = dict(incident)
        if not incident_dict.get('status'):
            incident_dict['status'] = 'open'
        if not incident_dict.get('created_at'):
            incident_dict['created_at'] = datetime.utcnow()
        incident_list.append(Incident(**incident_dict))
    return incident_list

@app.get("/incidents/stats", response_model=List[IncidentStats])
async def get_incident_stats_endpoint(
    server_id: Optional[int] = None,
    current_user: User = Depends(get_current_active_user)
):
    """Get incident statistics"""
    stats = await get_incident_stats(server_id=server_id)
    stats_list = []
    for stat in stats:
        stat_dict = dict(stat)
        if not stat_dict.get('status'):
            stat_dict['status'] = 'unknown'
        stats_list.append(IncidentStats(**stat_dict))
    return stats_list

@app.get("/incidents/{incident_id}", response_model=Incident)
async def get_incident_endpoint(
    incident_id: int,
    current_user: User = Depends(get_current_active_user)
):
    """Get a specific incident"""
    incident = await get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    incident_dict = dict(incident)
    if not incident_dict.get('status'):
        incident_dict['status'] = 'open'
    if not incident_dict.get('created_at'):
        incident_dict['created_at'] = datetime.utcnow()
    
    return Incident(**incident_dict)

@app.patch("/incidents/{incident_id}/status")
async def update_incident_status_endpoint(
    incident_id: int,
    status_update: IncidentUpdate,
    current_user: User = Depends(get_current_active_user)
):
    """Update incident status"""
    incident = await update_incident_status(
        incident_id, 
        status_update.status, 
        current_user.id,
        status_update.resolved_notes
    )
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    incident_dict = dict(incident)
    if not incident_dict.get('status'):
        incident_dict['status'] = 'open'
    if not incident_dict.get('created_at'):
        incident_dict['created_at'] = datetime.utcnow()
    
    return Incident(**incident_dict)

@app.get("/incidents/count")
async def get_incident_count_endpoint(
    status: str = None,
    server_id: Optional[int] = None,
    current_user: User = Depends(get_current_active_user)
):
    """Get incident count"""
    count = await get_incidents_count(status=status, server_id=server_id)
    return {"count": count}

# ==================== AGENT DATA ENDPOINTS ====================

@app.post("/agent/data", status_code=201)
async def receive_agent_data(
    data: dict = Body(...), 
    current_user: User = Depends(get_agent_user)
):
    """
    Receive periodic data from agent (Agent/Admin only)
    """
    print(f"📥 Received agent data from {current_user.username}")
    
    # Extract server information
    server_id = None
    hostname = data.get('hostname')
    if hostname:
        server = await get_server_by_hostname(hostname)
        if server:
            server_id = server['id']
            # Update server last seen
            await update_server_last_seen(server_id)
        else:
            # Create new server if it doesn't exist
            server_id = await create_server({
                "hostname": hostname,
                "ip_address": data.get('ip_address', ''),
                "description": f"Auto-discovered server: {hostname}",
                "os_type": data.get('os_type', 'unknown'),
                "os_version": data.get('os_version', ''),
                "tags": ["auto-discovered"]
            })
    
    # Ensure timestamp is properly formatted
    if 'timestamp' not in data:
        data['timestamp'] = datetime.utcnow().isoformat() + 'Z'
    else:
        if not data['timestamp'].endswith('Z'):
            data['timestamp'] = data['timestamp'] + 'Z'
    
    # Store agent data first
    data_id = await create_agent_data(data, server_id)
    if not data_id:
        raise HTTPException(status_code=500, detail="Failed to store agent data")
    
    print(f"✅ Agent data stored with ID: {data_id}")
    
    # Enhanced data processing with AI analysis
    enhanced_data = EnhancedAgentData(**data)
    
    # Get historical data for AI analysis
    historical_data = await get_historical_metrics(server_id=server_id, limit=50)
    
    # Generate AI insights
    ai_insights = await ai_service.generate_insights(data, historical_data)
    
    # Store AI insights
    for insight in ai_insights:
        await create_ai_insight({
            "metric_type": insight["metric_type"],
            "insight_type": insight["insight_type"],
            "message": insight["message"],
            "confidence": insight["confidence"],
            "action": insight.get("action"),
            "server_id": server_id
        })
    
    # Check for alerts
    triggered_alerts = await check_agent_data_for_alerts(data, data_id, server_id)
    
    # Check for suspicious processes
    if data.get('processes'):
        suspicious_processes = await evaluate_suspicious_processes(
            data['processes'], 
            data_id, 
            hostname or 'unknown',
            server_id
        )
        triggered_alerts.extend(suspicious_processes)
    
    # Broadcast updates
    await manager.broadcast({
        "type": "agent_data_update",
        "data": data,
        "data_id": data_id,
        "server_id": server_id,
        "timestamp": datetime.utcnow().isoformat() + 'Z'
    })
    
    # Broadcast AI insights
    if ai_insights:
        await manager.broadcast_ai({
            "type": "ai_insights",
            "insights": ai_insights,
            "server_id": server_id,
            "timestamp": datetime.utcnow().isoformat() + 'Z'
        })
    
    # Broadcast new incidents
    for alert in triggered_alerts:
        await manager.broadcast({
            "type": "new_incident",
            "incident": alert["incident"],
            "server_id": server_id,
            "timestamp": datetime.utcnow().isoformat() + 'Z'
        })
    
    return {
        "message": "Agent data received", 
        "data_id": data_id,
        "server_id": server_id,
        "triggered_alerts": len(triggered_alerts),
        "ai_insights": len(ai_insights)
    }

@app.get("/agent/data/latest")
async def get_latest_agent_data_endpoint(
    server_id: Optional[int] = None,
    current_user: User = Depends(get_guest_user)
):
    """
    Return latest agent data entry (Any authenticated user)
    """
    data = await get_latest_agent_data(server_id)
    if not data:
        return {"data": None}
    
    data_dict = dict(data)
    if data_dict.get('timestamp') and isinstance(data_dict['timestamp'], datetime):
        data_dict['timestamp'] = data_dict['timestamp'].isoformat() + 'Z'
    
    return {"data": data_dict}

@app.get("/agent/data")
async def get_all_agent_data_endpoint(
    server_id: Optional[int] = None,
    limit: int = 1000,
    current_user: User = Depends(get_guest_user)
):
    """
    Return all agent data entries (Any authenticated user)
    """
    data = await get_all_agent_data(server_id, limit)
    
    data_list = []
    for item in data:
        item_dict = dict(item)
        if item_dict.get('timestamp') and isinstance(item_dict['timestamp'], datetime):
            item_dict['timestamp'] = item_dict['timestamp'].isoformat() + 'Z'
        data_list.append(item_dict)
    
    return {"data": data_list}

@app.get("/agent/data/count")
async def get_agent_data_count(
    server_id: Optional[int] = None,
    current_user: User = Depends(get_guest_user)
):
    """
    Return count of agent data entries (Any authenticated user)
    """
    data = await get_all_agent_data(server_id)
    return {"count": len(data)}

# Enhanced Agent Data with filtering
@app.get("/agent/data/filtered")
async def get_filtered_agent_data(
    server_id: Optional[int] = None,
    start_date: str = None,
    end_date: str = None,
    hostname: str = None,
    min_cpu: float = None,
    max_cpu: float = None,
    min_memory: float = None,
    max_memory: float = None,
    current_user: User = Depends(get_guest_user)
):
    """Get filtered agent data with various filters"""
    try:
        query = """
        SELECT ad.*, s.hostname as server_hostname 
        FROM agent_data ad 
        LEFT JOIN servers s ON ad.server_id = s.id 
        WHERE 1=1
        """
        params = {}
        
        if server_id is not None:
            query += " AND ad.server_id = :server_id"
            params["server_id"] = server_id
            
        if start_date:
            query += " AND ad.timestamp >= :start_date"
            params["start_date"] = start_date
            
        if end_date:
            query += " AND ad.timestamp <= :end_date" 
            params["end_date"] = end_date
            
        if hostname:
            query += " AND s.hostname LIKE :hostname"
            params["hostname"] = f"%{hostname}%"
            
        query += " ORDER BY ad.created_at DESC"
        
        results = await database.fetch_all(query, params)
        
        filtered_data = []
        for result in results:
            result_dict = dict(result)
            if 'data' in result_dict and isinstance(result_dict['data'], str):
                try:
                    data_obj = json.loads(result_dict['data'])
                    
                    if min_cpu is not None and data_obj.get('cpu_usage', 0) < min_cpu:
                        continue
                    if max_cpu is not None and data_obj.get('cpu_usage', 0) > max_cpu:
                        continue
                        
                    if min_memory is not None and data_obj.get('memory_usage', 0) < min_memory:
                        continue
                    if max_memory is not None and data_obj.get('memory_usage', 0) > max_memory:
                        continue
                    
                    result_dict['data'] = data_obj
                    filtered_data.append(result_dict)
                    
                except json.JSONDecodeError:
                    continue
        
        return {"data": filtered_data, "total": len(filtered_data)}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Filter error: {str(e)}")

# Enhanced Incidents with filtering
@app.get("/incidents/filtered")
async def get_filtered_incidents(
    server_id: Optional[int] = None,
    status: str = None,
    severity: str = None,
    incident_type: str = None,
    start_date: str = None,
    end_date: str = None,
    current_user: User = Depends(get_current_active_user)
):
    """Get filtered incidents"""
    query = """
    SELECT i.*, s.hostname as server_hostname 
    FROM incidents i 
    LEFT JOIN servers s ON i.server_id = s.id 
    WHERE 1=1
    """
    params = {}
    
    if server_id is not None:
        query += " AND i.server_id = :server_id"
        params["server_id"] = server_id
        
    if status:
        query += " AND i.status = :status"
        params["status"] = status
        
    if severity:
        query += " AND i.severity = :severity"
        params["severity"] = severity
        
    if incident_type:
        query += " AND i.incident_type = :incident_type"
        params["incident_type"] = incident_type
        
    if start_date:
        query += " AND i.created_at >= :start_date"
        params["start_date"] = start_date
        
    if end_date:
        query += " AND i.created_at <= :end_date"
        params["end_date"] = end_date
        
    query += " ORDER BY i.created_at DESC"
    
    results = await database.fetch_all(query, params)
    
    parsed_results = []
    for result in results:
        result_dict = dict(result)
        if 'metadata' in result_dict and result_dict['metadata'] and isinstance(result_dict['metadata'], str):
            try:
                result_dict['metadata'] = json.loads(result_dict['metadata'])
            except json.JSONDecodeError:
                result_dict['metadata'] = {}
        parsed_results.append(result_dict)
    
    return parsed_results

# Drill-down endpoint for specific metric details
@app.get("/agent/data/metric-details")
async def get_metric_details(
    metric: str,
    server_id: Optional[int] = None,
    value_range: str = None,
    hostname: str = None,
    current_user: User = Depends(get_guest_user)
):
    """Get detailed data for a specific metric (drill-down)"""
    try:
        query = """
        SELECT ad.*, s.hostname as server_hostname 
        FROM agent_data ad 
        LEFT JOIN servers s ON ad.server_id = s.id 
        WHERE 1=1
        """
        params = {}
        
        if server_id is not None:
            query += " AND ad.server_id = :server_id"
            params["server_id"] = server_id
            
        if hostname:
            query += " AND s.hostname LIKE :hostname"
            params["hostname"] = f"%{hostname}%"
            
        results = await database.fetch_all(query, params)
        
        detailed_data = []
        for result in results:
            result_dict = dict(result)
            if 'data' in result_dict and isinstance(result_dict['data'], str):
                try:
                    data_obj = json.loads(result_dict['data'])
                    metric_value = data_obj.get(metric)
                    
                    if metric_value is not None:
                        if value_range:
                            min_val, max_val = map(float, value_range.split('-'))
                            if not (min_val <= metric_value <= max_val):
                                continue
                        
                        detailed_data.append({
                            "id": result_dict["id"],
                            "timestamp": result_dict.get("timestamp"),
                            "server_id": result_dict.get("server_id"),
                            "server_hostname": result_dict.get("server_hostname"),
                            "metric_value": metric_value,
                            "full_data": data_obj
                        })
                        
                except json.JSONDecodeError:
                    continue
        
        return {"metric": metric, "data": detailed_data}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Metric details error: {str(e)}")

# ==================== EXPORT ENDPOINTS ====================

@app.get("/export/agent-data/csv")
async def export_agent_data_csv(
    server_id: Optional[int] = None,
    start_date: str = None,
    end_date: str = None,
    hostname: str = None,
    min_cpu: float = None,
    max_cpu: float = None,
    min_memory: float = None,
    max_memory: float = None,
    current_user: User = Depends(get_guest_user)
):
    """Export filtered agent data as CSV"""
    try:
        query = """
        SELECT ad.*, s.hostname as server_hostname 
        FROM agent_data ad 
        LEFT JOIN servers s ON ad.server_id = s.id 
        WHERE 1=1
        """
        params = {}
        
        if server_id is not None:
            query += " AND ad.server_id = :server_id"
            params["server_id"] = server_id
            
        if start_date:
            query += " AND ad.timestamp >= :start_date"
            params["start_date"] = start_date
            
        if end_date:
            query += " AND ad.timestamp <= :end_date" 
            params["end_date"] = end_date
            
        if hostname:
            query += " AND s.hostname LIKE :hostname"
            params["hostname"] = f"%{hostname}%"
            
        results = await database.fetch_all(query, params)
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        writer.writerow([
            'ID', 'Server', 'Timestamp', 'Hostname', 'CPU Usage (%)', 
            'Memory Usage (%)', 'Disk Usage (%)', 
            'Bytes Sent', 'Bytes Received', 'Process Count'
        ])
        
        for result in results:
            result_dict = dict(result)
            if 'data' in result_dict and isinstance(result_dict['data'], str):
                try:
                    data_obj = json.loads(result_dict['data'])
                    
                    if min_cpu is not None and data_obj.get('cpu_usage', 0) < min_cpu:
                        continue
                    if max_cpu is not None and data_obj.get('cpu_usage', 0) > max_cpu:
                        continue
                    if min_memory is not None and data_obj.get('memory_usage', 0) < min_memory:
                        continue
                    if max_memory is not None and data_obj.get('memory_usage', 0) > max_memory:
                        continue
                    
                    writer.writerow([
                        result_dict['id'],
                        result_dict.get('server_hostname', ''),
                        result_dict.get('timestamp', ''),
                        data_obj.get('hostname', ''),
                        data_obj.get('cpu_usage', ''),
                        data_obj.get('memory_usage', ''),
                        data_obj.get('disk_usage', ''),
                        data_obj.get('network_activity', {}).get('bytes_sent', ''),
                        data_obj.get('network_activity', {}).get('bytes_received', ''),
                        len(data_obj.get('processes', []))
                    ])
                    
                except json.JSONDecodeError:
                    continue
        
        output.seek(0)
        filename = f"agent_data_export_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
        
        return StreamingResponse(
            io.BytesIO(output.getvalue().encode('utf-8')),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Export error: {str(e)}")

@app.get("/export/incidents/csv")
async def export_incidents_csv(
    server_id: Optional[int] = None,
    status: str = None,
    severity: str = None,
    incident_type: str = None,
    start_date: str = None,
    end_date: str = None,
    current_user: User = Depends(get_current_active_user)
):
    """Export filtered incidents as CSV"""
    try:
        incidents = await get_filtered_incidents(
            server_id=server_id,
            status=status, 
            severity=severity, 
            incident_type=incident_type,
            start_date=start_date, 
            end_date=end_date
        )
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        writer.writerow([
            'ID', 'Server', 'Type', 'Message', 'Severity', 'Status',
            'Created At', 'Hostname', 'Metric Value', 'Threshold'
        ])
        
        for incident in incidents:
            metadata = incident.get('metadata', {})
            writer.writerow([
                incident['id'],
                incident.get('server_hostname', ''),
                incident['incident_type'],
                incident['message'],
                incident['severity'],
                incident['status'],
                incident['created_at'],
                metadata.get('hostname', ''),
                metadata.get('metric_value', ''),
                metadata.get('threshold', '')
            ])
        
        output.seek(0)
        filename = f"incidents_export_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
        
        return StreamingResponse(
            io.BytesIO(output.getvalue().encode('utf-8')),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Incidents export error: {str(e)}")

@app.get("/export/dashboard-report")
async def export_dashboard_report(
    server_id: Optional[int] = None,
    start_date: str = None,
    end_date: str = None,
    current_user: User = Depends(get_current_active_user)
):
    """Export comprehensive dashboard report"""
    try:
        agent_data_response = await get_filtered_agent_data(
            server_id=server_id,
            start_date=start_date, 
            end_date=end_date
        )
        incidents = await get_filtered_incidents(
            server_id=server_id,
            start_date=start_date, 
            end_date=end_date
        )
        incident_stats = await get_incident_stats(server_id=server_id)
        ai_insights = await get_ai_insights(server_id=server_id, limit=20)
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        writer.writerow(['PURPLETEAM DASHBOARD REPORT - WITH AI INSIGHTS'])
        writer.writerow([f'Generated: {datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")}'])
        if server_id:
            server = await get_server_by_id(server_id)
            writer.writerow([f'Server: {server["hostname"] if server else "Unknown"}'])
        writer.writerow([f'Period: {start_date or "Start"} to {end_date or "End"}'])
        writer.writerow([])
        
        writer.writerow(['SUMMARY'])
        writer.writerow(['Total Data Entries:', agent_data_response.get('total', 0)])
        writer.writerow(['Total Incidents:', len(incidents)])
        writer.writerow(['AI Insights Generated:', len(ai_insights)])
        writer.writerow([])
        
        writer.writerow(['INCIDENT STATISTICS'])
        writer.writerow(['Status', 'Count'])
        for stat in incident_stats:
            writer.writerow([stat['status'], stat['count']])
        writer.writerow([])
        
        writer.writerow(['AI INSIGHTS (Recent)'])
        writer.writerow(['Type', 'Message', 'Confidence', 'Action'])
        for insight in ai_insights[:10]:
            writer.writerow([
                insight['insight_type'],
                insight['message'][:50] + '...' if len(insight['message']) > 50 else insight['message'],
                f"{insight['confidence']:.2f}",
                insight.get('action', '')
            ])
        writer.writerow([])
        
        writer.writerow(['RECENT INCIDENTS (Last 10)'])
        writer.writerow(['ID', 'Server', 'Type', 'Severity', 'Status', 'Message', 'Created'])
        for incident in incidents[:10]:
            writer.writerow([
                incident['id'],
                incident.get('server_hostname', ''),
                incident['incident_type'],
                incident['severity'],
                incident['status'],
                incident['message'][:50] + '...' if len(incident['message']) > 50 else incident['message'],
                incident['created_at']
            ])
        
        output.seek(0)
        filename = f"dashboard_report_ai_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
        
        return StreamingResponse(
            io.BytesIO(output.getvalue().encode('utf-8')),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Report export error: {str(e)}")

# ==================== DASHBOARD LAYOUTS ENDPOINTS ====================

@app.get("/dashboard/layouts", response_model=List[dict])
async def get_user_dashboard_layouts_endpoint(current_user: User = Depends(get_current_active_user)):
    """Get all dashboard layouts for current user"""
    layouts = await get_user_dashboard_layouts(current_user.id)
    
    parsed_layouts = []
    for layout in layouts:
        layout_dict = dict(layout)
        for field in ['layout', 'widgets', 'filters']:
            if layout_dict.get(field) and isinstance(layout_dict[field], str):
                try:
                    layout_dict[field] = json.loads(layout_dict[field])
                except json.JSONDecodeError:
                    layout_dict[field] = {}
        parsed_layouts.append(layout_dict)
    
    return parsed_layouts

@app.get("/dashboard/layouts/default", response_model=dict)
async def get_default_dashboard_layout_endpoint(current_user: User = Depends(get_current_active_user)):
    """Get user's default dashboard layout"""
    layout = await get_default_layout(current_user.id)
    if not layout:
        return {
            "id": None,
            "name": "Default Layout",
            "layout": {},
            "widgets": {},
            "filters": {},
            "is_default": True
        }
    
    layout_dict = dict(layout)
    for field in ['layout', 'widgets', 'filters']:
        if layout_dict.get(field) and isinstance(layout_dict[field], str):
            try:
                layout_dict[field] = json.loads(layout_dict[field])
            except json.JSONDecodeError:
                layout_dict[field] = {}
    
    return layout_dict

@app.get("/dashboard/layouts/{layout_id}", response_model=dict)
async def get_dashboard_layout_endpoint(layout_id: int, current_user: User = Depends(get_current_active_user)):
    """Get specific dashboard layout"""
    layout = await get_dashboard_layout(layout_id, current_user.id)
    if not layout:
        raise HTTPException(status_code=404, detail="Layout not found")
    
    layout_dict = dict(layout)
    for field in ['layout', 'widgets', 'filters']:
        if layout_dict.get(field) and isinstance(layout_dict[field], str):
            try:
                layout_dict[field] = json.loads(layout_dict[field])
            except json.JSONDecodeError:
                layout_dict[field] = {}
    
    return layout_dict

@app.post("/dashboard/layouts", response_model=dict)
async def create_dashboard_layout_endpoint(
    layout_data: dict = Body(...),
    current_user: User = Depends(get_current_active_user)
):
    """Create new dashboard layout"""
    layout_id = await create_dashboard_layout(
        user_id=current_user.id,
        name=layout_data.get("name", "New Layout"),
        layout=layout_data.get("layout", {}),
        widgets=layout_data.get("widgets", {}),
        filters=layout_data.get("filters", {})
    )
    if not layout_id:
        raise HTTPException(status_code=500, detail="Failed to create layout")
    
    layout = await get_dashboard_layout(layout_id, current_user.id)
    layout_dict = dict(layout)
    for field in ['layout', 'widgets', 'filters']:
        if layout_dict.get(field) and isinstance(layout_dict[field], str):
            try:
                layout_dict[field] = json.loads(layout_dict[field])
            except json.JSONDecodeError:
                layout_dict[field] = {}
    
    return layout_dict

@app.put("/dashboard/layouts/{layout_id}", response_model=dict)
async def update_dashboard_layout_endpoint(
    layout_id: int,
    layout_data: dict = Body(...),
    current_user: User = Depends(get_current_active_user)
):
    """Update dashboard layout"""
    layout = await update_dashboard_layout(
        layout_id=layout_id,
        user_id=current_user.id,
        name=layout_data.get("name"),
        layout=layout_data.get("layout"),
        widgets=layout_data.get("widgets"),
        filters=layout_data.get("filters")
    )
    if not layout:
        raise HTTPException(status_code=404, detail="Layout not found")
    
    layout_dict = dict(layout)
    for field in ['layout', 'widgets', 'filters']:
        if layout_dict.get(field) and isinstance(layout_dict[field], str):
            try:
                layout_dict[field] = json.loads(layout_dict[field])
            except json.JSONDecodeError:
                layout_dict[field] = {}
    
    return layout_dict

@app.delete("/dashboard/layouts/{layout_id}")
async def delete_dashboard_layout_endpoint(layout_id: int, current_user: User = Depends(get_current_active_user)):
    """Delete dashboard layout"""
    success = await delete_dashboard_layout(layout_id, current_user.id)
    if not success:
        raise HTTPException(status_code=404, detail="Layout not found")
    return {"message": "Layout deleted successfully"}

@app.patch("/dashboard/layouts/{layout_id}/set-default")
async def set_default_dashboard_layout_endpoint(layout_id: int, current_user: User = Depends(get_current_active_user)):
    """Set a dashboard layout as default"""
    success = await set_default_layout(layout_id, current_user.id)
    if not success:
        raise HTTPException(status_code=404, detail="Layout not found")
    return {"message": "Layout set as default"}

# ==================== SECURITY AND MONITORING ENDPOINTS ====================

@app.post("/slack/test")
async def test_slack_alert(current_user: User = Depends(get_agent_user)):
    """Test Slack alert functionality (Agent/Admin only)"""
    test_message = f"🧪 Test alert from PurpleTeam Dashboard - {datetime.utcnow().isoformat()}"
    send_slack_alert(test_message)
    return {"message": "Slack test alert sent"}

@app.get("/security/suspicious-activities")
async def get_suspicious_activities_endpoint(current_user: User = Depends(get_admin_user)):
    """Get suspicious activities (Admin only)"""
    suspicious = await get_suspicious_activities()
    return {
        "suspicious_activities": [dict(activity) for activity in suspicious],
        "total": len(suspicious)
    }

# ==================== ENHANCED WEBSOCKET ENDPOINTS ====================

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        # Get initial data with proper error handling
        try:
            all_data = await get_all_agent_data(limit=100)
            latest_data = await get_latest_agent_data()
        except Exception as e:
            print(f"WebSocket data fetch error: {e}")
            all_data = []
            latest_data = None
        
        latest_data_dict = None
        if latest_data:
            latest_data_dict = dict(latest_data)
            if latest_data_dict.get('timestamp') and isinstance(latest_data_dict['timestamp'], datetime):
                latest_data_dict['timestamp'] = latest_data_dict['timestamp'].isoformat() + 'Z'
            # Parse JSON data field if it's a string
            if latest_data_dict.get('data') and isinstance(latest_data_dict['data'], str):
                try:
                    latest_data_dict['data'] = json.loads(latest_data_dict['data'])
                except json.JSONDecodeError:
                    latest_data_dict['data'] = {}
        
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
            data = await websocket.receive_text()
            await manager.broadcast({
                "type": "client_message",
                "message": f"Client says: {data}",
                "timestamp": datetime.utcnow().isoformat() + 'Z'
            })
            
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# Enhanced WebSocket handler for real-time AI insights
@app.websocket("/ws/ai")
async def websocket_ai_endpoint(websocket: WebSocket):
    await manager.connect_ai(websocket)
    try:
        # Get recent AI insights
        recent_insights = await get_recent_ai_insights(limit=10)
        
        await websocket.send_json({
            "type": "ai_connection_established",
            "message": "Connected to AI Insights WebSocket",
            "recent_insights": [dict(insight) for insight in recent_insights],
            "timestamp": datetime.utcnow().isoformat() + 'Z'
        })
        
        # Send periodic AI updates
        while True:
            # Generate new AI insights based on recent data
            historical_data = await get_historical_metrics(limit=50)
            if historical_data:
                current_metrics = historical_data[-1] if historical_data else {}
                ai_insights = await ai_service.generate_insights(current_metrics, historical_data)
                
                if ai_insights:
                    await websocket.send_json({
                        "type": "ai_insights_update",
                        "insights": ai_insights,
                        "timestamp": datetime.utcnow().isoformat() + 'Z'
                    })
            
            await asyncio.sleep(30)  # Send updates every 30 seconds
            
    except WebSocketDisconnect:
        manager.disconnect(websocket)

@app.get("/ws/status")
async def websocket_status():
    """Get WebSocket connection status"""
    all_data = await get_all_agent_data()
    return {
        "active_connections": len(manager.active_connections),
        "ai_connections": len(manager.ai_connections),
        "total_agent_data": len(all_data)
    }

# ==================== BASIC ENDPOINTS ====================

@app.get("/")
async def root():
    return {"message": "PurpleTeam Dashboard Backend with AI Insights - Online"}

@app.get("/health")
async def health_check():
    """Health check endpoint - No auth required for testing"""
    redis_status = "connected" if redis_client else "disconnected"
    
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat() + 'Z',
        "database_connected": True,
        "redis_connected": redis_status,
        "ai_services": "active",
        "version": "2.0.0"
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
    
    # Background task for AI analysis
    async def periodic_ai_analysis():
        while True:
            await asyncio.sleep(60)  # Run every minute
            try:
                # Get recent data for analysis
                historical_data = await get_historical_metrics(limit=100)
                if historical_data and len(historical_data) > 10:
                    current_metrics = historical_data[-1]
                    
                    # Generate AI insights
                    insights = await ai_service.generate_insights(current_metrics, historical_data)
                    
                    # Store insights
                    for insight in insights:
                        await create_ai_insight({
                            "metric_type": insight["metric_type"],
                            "insight_type": insight["insight_type"],
                            "message": insight["message"],
                            "confidence": insight["confidence"],
                            "action": insight.get("action")
                        })
                    
                    # Broadcast to AI WebSocket connections
                    if insights and manager.ai_connections:
                        await manager.broadcast_ai({
                            "type": "periodic_ai_analysis",
                            "insights": insights,
                            "timestamp": datetime.utcnow().isoformat() + 'Z'
                        })
                        
            except Exception as e:
                print(f"Periodic AI analysis error: {e}")
    
    asyncio.create_task(periodic_ai_analysis())

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
