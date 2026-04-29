# crud.py - Complete updated CRUD operations with all fixes
from database import database
from passlib.context import CryptContext
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Dict, Any, Union
import json
import ipaddress
import re
import logging
from enum import Enum

# Configure logging
logger = logging.getLogger(__name__)

# Password hashing
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")

# Enums for type safety
class UserRole(str, Enum):
    ADMIN = "admin"
    USER = "user"
    GUEST = "guest"
    VIEWER = "viewer"

class IncidentStatus(str, Enum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    CLOSED = "closed"

class SeverityLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

# ==================== USER CRUD OPERATIONS ====================

async def create_user(username: str, email: str, password: str, role: str = "guest", **kwargs) -> Optional[int]:
    """Create a new user with hashed password and additional metadata"""
    try:
        # Validate input
        if not username or not email or not password:
            logger.warning("Attempt to create user with missing required fields")
            return None
            
        # Check if user already exists
        existing_user = await get_user_by_username(username) or await get_user_by_email(email)
        if existing_user:
            logger.warning(f"User with username {username} or email {email} already exists")
            return None

        hashed_password = pwd_context.hash(password)
        query = """
        INSERT INTO users (username, email, hashed_password, role, full_name, department, phone_number, metadata)
        VALUES (:username, :email, :hashed_password, :role, :full_name, :department, :phone_number, :metadata)
        RETURNING id
        """
        values = {
            "username": username.strip().lower(),
            "email": email.strip().lower(),
            "hashed_password": hashed_password,
            "role": role,
            "full_name": kwargs.get("full_name"),
            "department": kwargs.get("department"),
            "phone_number": kwargs.get("phone_number"),
            "metadata": json.dumps(kwargs.get("metadata", {}))
        }
        result = await database.fetch_one(query, values)
        user_id = result["id"] if result else None
        
        if user_id:
            logger.info(f"Successfully created user {username} with ID {user_id}")
            # Log the activity
            await log_user_activity(
                user_id=user_id,
                username=username,
                activity_type="user_created",
                ip_address=kwargs.get("ip_address", ""),
                details={"role": role, "source": "registration"}
            )
        
        return user_id
    except Exception as e:
        logger.error(f"Error creating user {username}: {e}")
        return None

async def get_user_by_username(username: str) -> Optional[Dict]:
    """Get user by username (case-insensitive)"""
    query = """
    SELECT *, 
           COALESCE(disabled, FALSE) as disabled
    FROM users 
    WHERE LOWER(username) = LOWER(:username) 
    AND (disabled IS NULL OR disabled = FALSE)
    """
    result = await database.fetch_one(query, {"username": username})
    return dict(result) if result else None

async def get_user_by_email(email: str) -> Optional[Dict]:
    """Get user by email (case-insensitive)"""
    query = """
    SELECT *, 
           COALESCE(disabled, FALSE) as disabled
    FROM users 
    WHERE LOWER(email) = LOWER(:email) 
    AND (disabled IS NULL OR disabled = FALSE)
    """
    result = await database.fetch_one(query, {"email": email})
    return dict(result) if result else None

async def get_user_by_id(user_id: int) -> Optional[Dict]:
    """Get user by ID"""
    query = """
    SELECT *, 
           COALESCE(disabled, FALSE) as disabled
    FROM users 
    WHERE id = :id 
    AND (disabled IS NULL OR disabled = FALSE)
    """
    result = await database.fetch_one(query, {"id": user_id})
    if result:
        user_dict = dict(result)
        # Parse metadata if exists
        if user_dict.get('metadata') and isinstance(user_dict['metadata'], str):
            try:
                user_dict['metadata'] = json.loads(user_dict['metadata'])
            except json.JSONDecodeError:
                user_dict['metadata'] = {}
        return user_dict
    return None

async def get_all_users(include_disabled: bool = False, role: str = None) -> List[Dict]:
    """Get all users with optional filtering"""
    query = "SELECT * FROM users WHERE 1=1"
    values = {}
    
    if not include_disabled:
        query += " AND (disabled IS NULL OR disabled = FALSE)"
    
    if role:
        query += " AND role = :role"
        values["role"] = role
        
    query += " ORDER BY created_at DESC"
    
    results = await database.fetch_all(query, values)
    users = []
    for result in results:
        user_dict = dict(result)
        if user_dict.get('metadata') and isinstance(user_dict['metadata'], str):
            try:
                user_dict['metadata'] = json.loads(user_dict['metadata'])
            except json.JSONDecodeError:
                user_dict['metadata'] = {}
        users.append(user_dict)
    
    return users

async def update_user_last_login(user_id: int, ip_address: str = None) -> bool:
    """Update user last login timestamp and IP"""
    try:
        query = """
        UPDATE users 
        SET last_login = CURRENT_TIMESTAMP, 
            last_login_ip = :ip_address,
            login_count = COALESCE(login_count, 0) + 1
        WHERE id = :id
        """
        await database.execute(query, {"id": user_id, "ip_address": ip_address})
        return True
    except Exception as e:
        logger.error(f"Error updating last login for user {user_id}: {e}")
        return False

async def update_user_role(user_id: int, role: str, updated_by: int = None) -> bool:
    """Update user role with audit trail"""
    try:
        query = "UPDATE users SET role = :role WHERE id = :id"
        await database.execute(query, {"id": user_id, "role": role})
        
        # Log the role change
        if updated_by:
            user = await get_user_by_id(user_id)
            updater = await get_user_by_id(updated_by)
            await log_user_activity(
                user_id=updated_by,
                username=updater.get('username', 'system') if updater else 'system',
                activity_type="role_updated",
                details={
                    "target_user_id": user_id,
                    "target_username": user.get('username', 'unknown') if user else 'unknown',
                    "old_role": user.get('role') if user else 'unknown',
                    "new_role": role
                }
            )
        return True
    except Exception as e:
        logger.error(f"Error updating role for user {user_id}: {e}")
        return False

async def disable_user(user_id: int, disabled_by: int = None) -> bool:
    """Disable a user account"""
    try:
        query = "UPDATE users SET disabled = true, disabled_at = CURRENT_TIMESTAMP WHERE id = :id"
        await database.execute(query, {"id": user_id})
        
        # Log the disable action
        if disabled_by:
            user = await get_user_by_id(user_id)
            disabler = await get_user_by_id(disabled_by)
            await log_user_activity(
                user_id=disabled_by,
                username=disabler.get('username', 'system') if disabler else 'system',
                activity_type="user_disabled",
                details={
                    "target_user_id": user_id,
                    "target_username": user.get('username', 'unknown') if user else 'unknown'
                }
            )
        return True
    except Exception as e:
        logger.error(f"Error disabling user {user_id}: {e}")
        return False

async def enable_user(user_id: int, enabled_by: int = None) -> bool:
    """Enable a user account"""
    try:
        query = "UPDATE users SET disabled = false, disabled_at = NULL WHERE id = :id"
        await database.execute(query, {"id": user_id})
        
        # Log the enable action
        if enabled_by:
            user = await get_user_by_id(user_id)
            enabler = await get_user_by_id(enabled_by)
            await log_user_activity(
                user_id=enabled_by,
                username=enabler.get('username', 'system') if enabler else 'system',
                activity_type="user_enabled",
                details={
                    "target_user_id": user_id,
                    "target_username": user.get('username', 'unknown') if user else 'unknown'
                }
            )
        return True
    except Exception as e:
        logger.error(f"Error enabling user {user_id}: {e}")
        return False

async def update_user_password(user_id: int, new_password: str) -> bool:
    """Update user password"""
    try:
        hashed_password = pwd_context.hash(new_password)
        query = """
        UPDATE users 
        SET hashed_password = :hashed_password, 
            password_changed_at = CURRENT_TIMESTAMP,
            force_password_change = false
        WHERE id = :id
        """
        await database.execute(query, {"id": user_id, "hashed_password": hashed_password})
        
        # Log password change
        await log_user_activity(
            user_id=user_id,
            activity_type="password_changed",
            details={"source": "user_action"}
        )
        return True
    except Exception as e:
        logger.error(f"Error updating password for user {user_id}: {e}")
        return False

async def delete_user(user_id: int, deleted_by: int = None) -> bool:
    """Permanently delete a user (use with caution)"""
    try:
        # First, get user info for logging
        user = await get_user_by_id(user_id)
        if not user:
            return False
            
        query = "DELETE FROM users WHERE id = :user_id"
        result = await database.execute(query, {"user_id": user_id})
        
        if result > 0 and deleted_by:
            # Log the deletion
            deleter = await get_user_by_id(deleted_by)
            await log_user_activity(
                user_id=deleted_by,
                username=deleter.get('username', 'system') if deleter else 'system',
                activity_type="user_deleted",
                details={
                    "deleted_user_id": user_id,
                    "deleted_username": user.get('username', 'unknown')
                }
            )
        
        return result > 0
    except Exception as e:
        logger.error(f"Error deleting user {user_id}: {e}")
        return False

async def verify_user_credentials(username: str, password: str) -> Optional[Dict]:
    """Verify user credentials and return user if valid"""
    user = await get_user_by_username(username) or await get_user_by_email(username)
    if not user:
        logger.warning(f"Login attempt for non-existent user: {username}")
        return None
        
    if not verify_password(password, user['hashed_password']):
        logger.warning(f"Failed login attempt for user: {username}")
        return None
        
    return user

# Password verification function
def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash"""
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception as e:
        logger.error(f"Password verification error: {e}")
        return False

# ==================== USER PREFERENCES CRUD OPERATIONS ====================

async def create_user_preference(user_id: int, preference_data: dict) -> Optional[int]:
    """Create or update user preference"""
    try:
        preference_type = preference_data.get("preference_type", "general")
        preference_value = preference_data.get("preference_value", {})
        
        query = """
        INSERT INTO user_preferences (user_id, preference_type, preference_value)
        VALUES (:user_id, :preference_type, :preference_value)
        ON CONFLICT (user_id, preference_type) 
        DO UPDATE SET preference_value = :preference_value, updated_at = CURRENT_TIMESTAMP
        RETURNING id
        """
        values = {
            "user_id": user_id,
            "preference_type": preference_type,
            "preference_value": json.dumps(preference_value)
        }
        result = await database.fetch_one(query, values)
        return result["id"] if result else None
    except Exception as e:
        logger.error(f"Error creating user preference: {e}")
        return None

async def get_user_preference(user_id: int, preference_type: str = "general") -> Optional[Dict]:
    """Get user preference by type"""
    query = """
    SELECT * FROM user_preferences 
    WHERE user_id = :user_id AND preference_type = :preference_type
    """
    result = await database.fetch_one(query, {
        "user_id": user_id,
        "preference_type": preference_type
    })
    if result:
        pref_dict = dict(result)
        if pref_dict.get('preference_value') and isinstance(pref_dict['preference_value'], str):
            try:
                pref_dict['preference_value'] = json.loads(pref_dict['preference_value'])
            except json.JSONDecodeError:
                pref_dict['preference_value'] = {}
        return pref_dict
    return None

async def get_all_user_preferences(user_id: int) -> List[Dict]:
    """Get all preferences for a user"""
    query = "SELECT * FROM user_preferences WHERE user_id = :user_id"
    results = await database.fetch_all(query, {"user_id": user_id})
    
    preferences = []
    for result in results:
        pref_dict = dict(result)
        if pref_dict.get('preference_value') and isinstance(pref_dict['preference_value'], str):
            try:
                pref_dict['preference_value'] = json.loads(pref_dict['preference_value'])
            except json.JSONDecodeError:
                pref_dict['preference_value'] = {}
        preferences.append(pref_dict)
    
    return preferences

async def delete_user_preference(user_id: int, preference_type: str) -> bool:
    """Delete user preference"""
    try:
        query = """
        DELETE FROM user_preferences 
        WHERE user_id = :user_id AND preference_type = :preference_type
        """
        result = await database.execute(query, {
            "user_id": user_id,
            "preference_type": preference_type
        })
        return result > 0
    except Exception as e:
        logger.error(f"Error deleting user preference: {e}")
        return False

async def update_user_preference(user_id: int, preference_data: dict) -> Optional[Dict]:
    """Update user preference"""
    try:
        preference_type = preference_data.get("preference_type", "general")
        preference_value = preference_data.get("preference_value", {})
        
        query = """
        UPDATE user_preferences 
        SET preference_value = :preference_value, updated_at = CURRENT_TIMESTAMP
        WHERE user_id = :user_id AND preference_type = :preference_type
        RETURNING *
        """
        values = {
            "user_id": user_id,
            "preference_type": preference_type,
            "preference_value": json.dumps(preference_value)
        }
        result = await database.fetch_one(query, values)
        if result:
            pref_dict = dict(result)
            if pref_dict.get('preference_value') and isinstance(pref_dict['preference_value'], str):
                try:
                    pref_dict['preference_value'] = json.loads(pref_dict['preference_value'])
                except json.JSONDecodeError:
                    pref_dict['preference_value'] = {}
            return pref_dict
        return None
    except Exception as e:
        logger.error(f"Error updating user preference: {e}")
        return None

# ==================== SERVER CRUD OPERATIONS ====================

async def create_server(server_data: dict, created_by: int = None) -> Optional[int]:
    """Create a new server entry"""
    try:
        # Validate required fields
        if not server_data.get("hostname"):
            logger.warning("Attempt to create server without hostname")
            return None

        query = """
        INSERT INTO servers (
            hostname, ip_address, description, os_type, os_version, 
            tags, monitoring_enabled, location, environment, criticality,
            created_by
        )
        VALUES (
            :hostname, :ip_address, :description, :os_type, :os_version, 
            :tags, :monitoring_enabled, :location, :environment, :criticality,
            :created_by
        )
        RETURNING id
        """
        values = {
            "hostname": server_data["hostname"].strip().lower(),
            "ip_address": server_data.get("ip_address", ""),
            "description": server_data.get("description", ""),
            "os_type": server_data.get("os_type", "unknown"),
            "os_version": server_data.get("os_version", ""),
            "tags": json.dumps(server_data.get("tags", [])),
            "monitoring_enabled": server_data.get("monitoring_enabled", True),
            "location": server_data.get("location", ""),
            "environment": server_data.get("environment", "production"),
            "criticality": server_data.get("criticality", "medium"),
            "created_by": created_by
        }
        result = await database.fetch_one(query, values)
        server_id = result["id"] if result else None
        
        if server_id and created_by:
            await log_user_activity(
                user_id=created_by,
                activity_type="server_created",
                details={
                    "server_id": server_id,
                    "hostname": server_data["hostname"],
                    "ip_address": server_data.get("ip_address", "")
                }
            )
        
        return server_id
    except Exception as e:
        logger.error(f"Error creating server: {e}")
        return None

async def get_all_servers(
    monitoring_enabled: bool = None,
    environment: str = None,
    criticality: str = None,
    limit: int = 1000
) -> List[Dict]:
    """Get all servers with optional filtering"""
    query = "SELECT * FROM servers WHERE 1=1"
    values = {"limit": limit}
    
    if monitoring_enabled is not None:
        query += " AND monitoring_enabled = :monitoring_enabled"
        values["monitoring_enabled"] = monitoring_enabled
        
    if environment:
        query += " AND environment = :environment"
        values["environment"] = environment
        
    if criticality:
        query += " AND criticality = :criticality"
        values["criticality"] = criticality
        
    query += " ORDER BY hostname LIMIT :limit"
    
    results = await database.fetch_all(query, values)
    servers = []
    for result in results:
        server_dict = dict(result)
        if server_dict.get('tags') and isinstance(server_dict['tags'], str):
            try:
                server_dict['tags'] = json.loads(server_dict['tags'])
            except json.JSONDecodeError:
                server_dict['tags'] = []
        servers.append(server_dict)
    
    return servers

async def get_server_by_id(server_id: int) -> Optional[Dict]:
    """Get server by ID"""
    query = "SELECT * FROM servers WHERE id = :id"
    result = await database.fetch_one(query, {"id": server_id})
    if result:
        server_dict = dict(result)
        if server_dict.get('tags') and isinstance(server_dict['tags'], str):
            try:
                server_dict['tags'] = json.loads(server_dict['tags'])
            except json.JSONDecodeError:
                server_dict['tags'] = []
        return server_dict
    return None

async def get_server_by_hostname(hostname: str) -> Optional[Dict]:
    """Get server by hostname"""
    query = "SELECT * FROM servers WHERE hostname = :hostname"
    result = await database.fetch_one(query, {"hostname": hostname})
    if result:
        server_dict = dict(result)
        if server_dict.get('tags') and isinstance(server_dict['tags'], str):
            try:
                server_dict['tags'] = json.loads(server_dict['tags'])
            except json.JSONDecodeError:
                server_dict['tags'] = []
        return server_dict
    return None

async def update_server_last_seen(server_id: int) -> bool:
    """Update server last seen timestamp"""
    try:
        query = """
        UPDATE servers 
        SET last_seen = CURRENT_TIMESTAMP,
            status = 'online'
        WHERE id = :id
        """
        await database.execute(query, {"id": server_id})
        return True
    except Exception as e:
        logger.error(f"Error updating last seen for server {server_id}: {e}")
        return False

async def update_server(server_id: int, server_data: dict, updated_by: int = None) -> Optional[Dict]:
    """Update server information"""
    try:
        query = """
        UPDATE servers 
        SET hostname = :hostname, 
            ip_address = :ip_address, 
            description = :description,
            os_type = :os_type, 
            os_version = :os_version, 
            tags = :tags,
            monitoring_enabled = :monitoring_enabled,
            location = :location,
            environment = :environment,
            criticality = :criticality,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = :id
        RETURNING *
        """
        values = {
            "id": server_id,
            "hostname": server_data["hostname"],
            "ip_address": server_data.get("ip_address", ""),
            "description": server_data.get("description", ""),
            "os_type": server_data.get("os_type", "unknown"),
            "os_version": server_data.get("os_version", ""),
            "tags": json.dumps(server_data.get("tags", [])),
            "monitoring_enabled": server_data.get("monitoring_enabled", True),
            "location": server_data.get("location", ""),
            "environment": server_data.get("environment", "production"),
            "criticality": server_data.get("criticality", "medium")
        }
        result = await database.fetch_one(query, values)
        
        if result and updated_by:
            await log_user_activity(
                user_id=updated_by,
                activity_type="server_updated",
                details={
                    "server_id": server_id,
                    "hostname": server_data["hostname"],
                    "changes": server_data
                }
            )
            
        if result:
            server_dict = dict(result)
            if server_dict.get('tags') and isinstance(server_dict['tags'], str):
                try:
                    server_dict['tags'] = json.loads(server_dict['tags'])
                except json.JSONDecodeError:
                    server_dict['tags'] = []
            return server_dict
        return None
    except Exception as e:
        logger.error(f"Error updating server {server_id}: {e}")
        return None

async def delete_server(server_id: int, deleted_by: int = None) -> bool:
    """Delete a server"""
    try:
        # Get server info for logging
        server = await get_server_by_id(server_id)
        if not server:
            return False
            
        query = "DELETE FROM servers WHERE id = :server_id"
        result = await database.execute(query, {"server_id": server_id})
        
        if result > 0 and deleted_by:
            await log_user_activity(
                user_id=deleted_by,
                activity_type="server_deleted",
                details={
                    "server_id": server_id,
                    "hostname": server.get('hostname', 'unknown')
                }
            )
        
        return result > 0
    except Exception as e:
        logger.error(f"Error deleting server {server_id}: {e}")
        return False

# ==================== AGENT DATA CRUD OPERATIONS ====================

async def create_agent_data(data: dict, server_id: Optional[int] = None) -> Optional[int]:
    """Create new agent data with comprehensive processing"""
    try:
        data_json = json.dumps(data)
        
        # Parse timestamp - ensure timezone awareness
        timestamp_str = data.get('timestamp')
        timestamp_obj = None
        
        if timestamp_str:
            try:
                if timestamp_str.endswith('Z'):
                    timestamp_str = timestamp_str[:-1]
                timestamp_obj = datetime.fromisoformat(timestamp_str)
                # Ensure timezone awareness
                if timestamp_obj.tzinfo is None:
                    timestamp_obj = timestamp_obj.replace(tzinfo=timezone.utc)
            except (ValueError, TypeError):
                logger.warning(f"Invalid timestamp format: {timestamp_str}, using current time")
                timestamp_obj = datetime.now(timezone.utc)
        else:
            timestamp_obj = datetime.now(timezone.utc)
        
        query = """
        INSERT INTO agent_data (server_id, data, timestamp, hostname, agent_version)
        VALUES (:server_id, :data, :timestamp, :hostname, :agent_version)
        RETURNING id
        """
        values = {
            "server_id": server_id,
            "data": data_json,
            "timestamp": timestamp_obj,
            "hostname": data.get('hostname', ''),
            "agent_version": data.get('agent_version', '')
        }
        
        result = await database.fetch_one(query, values)
        data_id = result["id"] if result else None
        
        # Check for alerts after creating agent data
        if data_id:
            await check_agent_data_for_alerts(data, data_id, server_id)
            
            # Generate AI insights
            await generate_ai_insights(data, server_id, data_id)
        
        return data_id
        
    except Exception as e:
        logger.error(f"Error creating agent data: {e}")
        return None

async def get_latest_agent_data(server_id: Optional[int] = None) -> Optional[Dict]:
    """Get latest agent data for a server or all servers"""
    query = """
    SELECT ad.*, s.hostname as server_hostname 
    FROM agent_data ad 
    LEFT JOIN servers s ON ad.server_id = s.id
    WHERE (:server_id IS NULL OR ad.server_id = :server_id)
    ORDER BY ad.created_at DESC 
    LIMIT 1
    """
    result = await database.fetch_one(query, {"server_id": server_id})
    if result:
        result_dict = dict(result)
        if 'data' in result_dict and isinstance(result_dict['data'], str):
            try:
                result_dict['data'] = json.loads(result_dict['data'])
            except json.JSONDecodeError:
                pass
        return result_dict
    return None

async def get_all_agent_data(
    server_id: Optional[int] = None, 
    limit: int = 1000,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None
) -> List[Dict]:
    """Get all agent data with filtering"""
    query = """
    SELECT ad.*, s.hostname as server_hostname 
    FROM agent_data ad 
    LEFT JOIN servers s ON ad.server_id = s.id
    WHERE (:server_id IS NULL OR ad.server_id = :server_id)
    """
    values = {"server_id": server_id, "limit": limit}
    
    if start_date:
        query += " AND ad.timestamp >= :start_date"
        values["start_date"] = start_date
        
    if end_date:
        query += " AND ad.timestamp <= :end_date"
        values["end_date"] = end_date
        
    query += " ORDER BY ad.created_at DESC LIMIT :limit"
    
    results = await database.fetch_all(query, values)
    
    parsed_results = []
    for result in results:
        result_dict = dict(result)
        if 'data' in result_dict and isinstance(result_dict['data'], str):
            try:
                result_dict['data'] = json.loads(result_dict['data'])
            except json.JSONDecodeError:
                pass
        parsed_results.append(result_dict)
    
    return parsed_results

async def get_agent_data_by_id(data_id: int) -> Optional[Dict]:
    """Get agent data by ID"""
    query = """
    SELECT ad.*, s.hostname as server_hostname 
    FROM agent_data ad 
    LEFT JOIN servers s ON ad.server_id = s.id
    WHERE ad.id = :id
    """
    result = await database.fetch_one(query, {"id": data_id})
    if result:
        result_dict = dict(result)
        if 'data' in result_dict and isinstance(result_dict['data'], str):
            try:
                result_dict['data'] = json.loads(result_dict['data'])
            except json.JSONDecodeError:
                pass
        return result_dict
    return None

async def get_agent_data_stats(server_id: Optional[int] = None) -> Dict:
    """Get comprehensive statistics about agent data"""
    query = """
    SELECT 
        COUNT(*) as total_records,
        MIN(created_at) as first_record,
        MAX(created_at) as last_record,
        COUNT(DISTINCT server_id) as unique_servers,
        COUNT(DISTINCT hostname) as unique_hostnames,
        AVG(LENGTH(data)) as avg_data_size
    FROM agent_data 
    WHERE (:server_id IS NULL OR server_id = :server_id)
    """
    result = await database.fetch_one(query, {"server_id": server_id})
    return dict(result) if result else {}

async def cleanup_old_agent_data(days: int = 30) -> int:
    """Clean up agent data older than specified days"""
    try:
        query = """
        DELETE FROM agent_data 
        WHERE created_at < (NOW() - INTERVAL (:days || ' days'))
        """
        result = await database.execute(query, {"days": days})
        logger.info(f"Cleaned up {result} old agent data records older than {days} days")
        return result
    except Exception as e:
        logger.error(f"Error cleaning up old agent data: {e}")
        return 0

# ==================== HISTORICAL METRICS OPERATIONS ====================

async def get_historical_metrics(
    server_id: Optional[int] = None,
    metric_name: str = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    limit: int = 1000
) -> List[Dict]:
    """Get historical metrics data with filtering"""
    try:
        query = """
        SELECT 
            ad.id,
            ad.server_id,
            ad.timestamp,
            ad.hostname,
            ad.data,
            s.hostname as server_hostname
        FROM agent_data ad
        LEFT JOIN servers s ON ad.server_id = s.id
        WHERE 1=1
        """
        values = {"limit": limit}
        
        if server_id is not None:
            query += " AND ad.server_id = :server_id"
            values["server_id"] = server_id
            
        if start_date:
            query += " AND ad.timestamp >= :start_date"
            values["start_date"] = start_date
            
        if end_date:
            query += " AND ad.timestamp <= :end_date"
            values["end_date"] = end_date
            
        query += " ORDER BY ad.timestamp DESC LIMIT :limit"
        
        results = await database.fetch_all(query, values)
        
        metrics = []
        for result in results:
            result_dict = dict(result)
            if result_dict.get('data') and isinstance(result_dict['data'], str):
                try:
                    data = json.loads(result_dict['data'])
                    # If specific metric is requested, extract it
                    if metric_name:
                        if '.' in metric_name:
                            # Handle nested metrics (e.g., "cpu.usage")
                            parts = metric_name.split('.')
                            value = data
                            for part in parts:
                                if isinstance(value, dict) and part in value:
                                    value = value[part]
                                else:
                                    value = None
                                    break
                            metric_value = value
                        else:
                            metric_value = data.get(metric_name)
                        
                        if metric_value is not None:
                            result_dict['metric_value'] = metric_value
                            result_dict['metric_name'] = metric_name
                            metrics.append(result_dict)
                    else:
                        # Return all data if no specific metric requested
                        result_dict['data'] = data
                        metrics.append(result_dict)
                except json.JSONDecodeError:
                    continue
        
        return metrics
        
    except Exception as e:
        logger.error(f"Error getting historical metrics: {e}")
        return []

async def get_metric_statistics(
    server_id: int,
    metric_name: str,
    start_date: str,
    end_date: str,
    aggregation: str = 'avg'  # avg, min, max, sum, count
) -> Optional[Dict]:
    """Get statistical analysis for a specific metric"""
    try:
        # Get the historical data first
        metrics = await get_historical_metrics(
            server_id=server_id,
            metric_name=metric_name,
            start_date=start_date,
            end_date=end_date,
            limit=10000  # High limit for statistical analysis
        )
        
        if not metrics:
            return None
            
        values = []
        for metric in metrics:
            if 'metric_value' in metric and metric['metric_value'] is not None:
                try:
                    values.append(float(metric['metric_value']))
                except (ValueError, TypeError):
                    continue
        
        if not values:
            return None
            
        # Calculate statistics
        if aggregation == 'avg':
            result = sum(values) / len(values)
        elif aggregation == 'min':
            result = min(values)
        elif aggregation == 'max':
            result = max(values)
        elif aggregation == 'sum':
            result = sum(values)
        elif aggregation == 'count':
            result = len(values)
        else:
            result = sum(values) / len(values)  # Default to avg
            
        return {
            "server_id": server_id,
            "metric_name": metric_name,
            "aggregation": aggregation,
            "value": result,
            "data_points": len(values),
            "period": {
                "start_date": start_date,
                "end_date": end_date
            }
        }
        
    except Exception as e:
        logger.error(f"Error getting metric statistics: {e}")
        return None

async def get_metrics_trend(
    server_id: Optional[int] = None,
    metric_name: str = None,
    time_window: str = '1h',
    aggregation: str = 'avg'
) -> List[Dict]:
    """Get metrics trend data for charts and analytics"""
    try:
        # Simplified time window calculation
        if time_window == '1h':
            cutoff_hours = 1
        elif time_window == '24h':
            cutoff_hours = 24
        elif time_window == '7d':
            cutoff_hours = 168  # 24 * 7
        elif time_window == '30d':
            cutoff_hours = 720  # 24 * 30
        else:
            cutoff_hours = 24  # Default

        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=cutoff_hours)
        
        # Rest of the function remains the same...
        metrics = await get_historical_metrics(
            server_id=server_id,
            metric_name=metric_name,
            limit=10000
        )
        
        if not metrics:
            return []
        
        filtered_metrics = [m for m in metrics if m.get('timestamp') and m['timestamp'] >= cutoff_time]
        
        trends = []
        if filtered_metrics:
            grouped_data = {}
            for metric in filtered_metrics:
                timestamp = metric['timestamp']
                hour_key = timestamp.strftime('%Y-%m-%d %H:00:00')
                
                if hour_key not in grouped_data:
                    grouped_data[hour_key] = []
                
                if 'metric_value' in metric:
                    grouped_data[hour_key].append(metric['metric_value'])
            
            for time_period, values in grouped_data.items():
                if values:
                    if aggregation == 'avg':
                        value = sum(values) / len(values)
                    elif aggregation == 'min':
                        value = min(values)
                    elif aggregation == 'max':
                        value = max(values)
                    else:
                        value = sum(values) / len(values)
                    
                    trends.append({
                        "time_period": time_period,
                        "server_id": server_id,
                        "value": round(value, 2),
                        "data_points": len(values),
                        "metric_name": metric_name or 'composite_metrics'
                    })
        
        return sorted(trends, key=lambda x: x['time_period'])
        
    except Exception as e:
        logger.error(f"Error getting metrics trend: {e}")
        return []

# ==================== ALERT EVALUATION FUNCTIONS ====================

async def check_agent_data_for_alerts(data: dict, data_id: int, server_id: int = None) -> List[Dict]:
    """Check agent data against alert rules and create incidents if triggered"""
    triggered_alerts = []
    
    try:
        # Get active alert rules
        if server_id:
            rules = await database.fetch_all(
                "SELECT * FROM alert_rules WHERE active = TRUE AND (server_id = :server_id OR server_id IS NULL)",
                {"server_id": server_id}
            )
        else:
            rules = await database.fetch_all(
                "SELECT * FROM alert_rules WHERE active = TRUE"
            )
        
        for rule in rules:
            rule_dict = dict(rule)
            metric_value = extract_metric_value(data, rule_dict['metric'])
            
            if metric_value is not None:
                is_triggered = evaluate_alert_condition(metric_value, rule_dict)
                
                if is_triggered:
                    # Check if similar incident already exists (avoid duplicates)
                    existing_incident = await get_recent_similar_incident(
                        rule_dict['id'], server_id, metric_value
                    )
                    
                    if not existing_incident:
                        # Create incident
                        incident_data = {
                            "server_id": server_id,
                            "alert_rule_id": rule_dict['id'],
                            "agent_data_id": data_id,
                            "incident_type": f"{rule_dict['metric']}_alert",
                            "message": f"Alert: {rule_dict['metric']} {rule_dict['comparison_operator']} {rule_dict['threshold_value']}. Current value: {metric_value}",
                            "severity": rule_dict['severity'],
                            "metadata": {
                                "metric": rule_dict['metric'],
                                "metric_value": metric_value,
                                "threshold": rule_dict['threshold_value'],
                                "comparison_operator": rule_dict['comparison_operator'],
                                "hostname": data.get('hostname', 'unknown'),
                                "rule_description": rule_dict.get('description', '')
                            }
                        }
                        
                        incident_id = await create_incident(incident_data)
                        
                        if incident_id:
                            triggered_alerts.append({
                                "rule": rule_dict,
                                "metric_value": metric_value,
                                "incident_id": incident_id,
                                "incident": incident_data
                            })
        
        # Check for suspicious processes
        processes = data.get('processes', [])
        hostname = data.get('hostname', 'unknown')
        if processes:
            suspicious_incidents = await evaluate_suspicious_processes(processes, data_id, hostname, server_id)
            triggered_alerts.extend(suspicious_incidents)
        
        # Check for security anomalies
        security_incidents = await evaluate_security_anomalies(data, data_id, server_id)
        triggered_alerts.extend(security_incidents)
        
        return triggered_alerts
        
    except Exception as e:
        logger.error(f"Error checking agent data for alerts: {e}")
        return []

def extract_metric_value(data: dict, metric_path: str) -> Optional[float]:
    """Extract metric value from nested data structure"""
    try:
        if '.' in metric_path:
            # Handle nested metrics (e.g., "cpu.usage")
            parts = metric_path.split('.')
            value = data
            for part in parts:
                if isinstance(value, dict) and part in value:
                    value = value[part]
                else:
                    return None
            return float(value) if value is not None else None
        else:
            # Simple metric
            value = data.get(metric_path)
            return float(value) if value is not None else None
    except (ValueError, TypeError, KeyError):
        return None

def evaluate_alert_condition(metric_value: float, rule: dict) -> bool:
    """Evaluate if alert condition is met"""
    operator = rule['comparison_operator']
    threshold = rule['threshold_value']
    
    try:
        if operator == '>':
            return metric_value > threshold
        elif operator == '>=':
            return metric_value >= threshold
        elif operator == '<':
            return metric_value < threshold
        elif operator == '<=':
            return metric_value <= threshold
        elif operator == '==':
            return metric_value == threshold
        elif operator == '!=':
            return metric_value != threshold
        else:
            logger.warning(f"Unknown comparison operator: {operator}")
            return False
    except Exception as e:
        logger.error(f"Error evaluating alert condition: {e}")
        return False

async def get_recent_similar_incident(rule_id: int, server_id: int, metric_value: float) -> Optional[Dict]:
    """Check for recent similar incidents to avoid duplicates"""
    query = """
    SELECT * FROM incidents 
    WHERE alert_rule_id = :rule_id 
    AND server_id = :server_id 
    AND status IN ('open', 'acknowledged')
    AND created_at >= (NOW() - INTERVAL '5 minutes')
    LIMIT 1
    """
    result = await database.fetch_one(query, {
        "rule_id": rule_id,
        "server_id": server_id
    })
    return dict(result) if result else None

async def evaluate_suspicious_processes(processes: list, data_id: int, hostname: str, server_id: int = None) -> List[Dict]:
    """Evaluate processes for suspicious activity"""
    suspicious_incidents = []
    suspicious_keywords = [
        'cryptominer', 'miner', 'backdoor', 'rootkit', 'keylogger', 
        'malware', 'ransomware', 'trojan', 'botnet', 'coinminer'
    ]
    
    suspicious_patterns = [
        r"minerd", r"cpuminer", r"xmrig", r"ccminer", 
        r"\.miner", r"mining", r"pool\."
    ]
    
    for process in processes:
        process_name = process.get('name', '').lower()
        process_cmd = process.get('cmd', '').lower()
        process_user = process.get('user', 'unknown')
        
        # Check against keywords
        for keyword in suspicious_keywords:
            if keyword in process_name or keyword in process_cmd:
                incident_data = await create_security_incident(
                    "suspicious_process_keyword",
                    f"Suspicious process detected: {process.get('name', 'unknown')} (contains '{keyword}')",
                    "high",
                    server_id,
                    data_id,
                    {
                        "process_name": process.get('name'),
                        "process_cmd": process.get('cmd'),
                        "process_pid": process.get('pid'),
                        "process_user": process_user,
                        "suspicious_keyword": keyword,
                        "hostname": hostname
                    }
                )
                if incident_data:
                    suspicious_incidents.append(incident_data)
                break
        
        # Check against patterns
        for pattern in suspicious_patterns:
            if re.search(pattern, process_name) or re.search(pattern, process_cmd):
                incident_data = await create_security_incident(
                    "suspicious_process_pattern",
                    f"Suspicious process detected matching pattern: {process.get('name', 'unknown')}",
                    "medium",
                    server_id,
                    data_id,
                    {
                        "process_name": process.get('name'),
                        "process_cmd": process.get('cmd'),
                        "process_pid": process.get('pid'),
                        "process_user": process_user,
                        "matched_pattern": pattern,
                        "hostname": hostname
                    }
                )
                if incident_data:
                    suspicious_incidents.append(incident_data)
                break
    
    return suspicious_incidents

async def evaluate_security_anomalies(data: dict, data_id: int, server_id: int = None) -> List[Dict]:
    """Evaluate data for security anomalies"""
    security_incidents = []
    hostname = data.get('hostname', 'unknown')
    
    # Check for unusual network connections
    network_connections = data.get('network_connections', [])
    for conn in network_connections:
        # Check for connections to known suspicious ports
        suspicious_ports = [4444, 5555, 6666, 7777, 8888, 9999, 1337, 31337]
        remote_port = conn.get('remote_port')
        if remote_port in suspicious_ports:
            incident_data = await create_security_incident(
                "suspicious_network_connection",
                f"Suspicious network connection to port {remote_port}",
                "medium",
                server_id,
                data_id,
                {
                    "local_address": conn.get('local_address'),
                    "remote_address": conn.get('remote_address'),
                    "remote_port": remote_port,
                    "protocol": conn.get('protocol'),
                    "hostname": hostname
                }
            )
            if incident_data:
                security_incidents.append(incident_data)
    
    # Check for unusual system load patterns
    cpu_usage = data.get('cpu_usage')
    if cpu_usage and cpu_usage > 95:  # Critical CPU usage
        incident_data = await create_security_incident(
            "critical_cpu_usage",
            f"Critical CPU usage detected: {cpu_usage}%",
            "high",
            server_id,
            data_id,
            {
                "cpu_usage": cpu_usage,
                "hostname": hostname
            }
        )
        if incident_data:
            security_incidents.append(incident_data)
    
    return security_incidents

async def create_security_incident(
    incident_type: str, 
    message: str, 
    severity: str, 
    server_id: int, 
    data_id: int, 
    metadata: dict
) -> Optional[Dict]:
    """Create a security incident"""
    incident_data = {
        "server_id": server_id,
        "agent_data_id": data_id,
        "incident_type": incident_type,
        "message": message,
        "severity": severity,
        "metadata": metadata
    }
    
    incident_id = await create_incident(incident_data)
    if incident_id:
        return {
            "incident_type": incident_type,
            "incident_id": incident_id,
            "incident": incident_data
        }
    return None

# ==================== AI INSIGHTS GENERATION ====================

async def generate_ai_insights(data: dict, server_id: int = None, data_id: int = None) -> List[Dict]:
    """Generate AI insights from agent data"""
    insights = []
    
    try:
        # Analyze CPU usage patterns
        cpu_usage = data.get('cpu_usage')
        if cpu_usage is not None:
            if cpu_usage > 80:
                insights.append(await create_ai_insight({
                    "metric_type": "cpu_usage",
                    "insight_type": "performance_alert",
                    "message": f"High CPU usage detected: {cpu_usage}%. Consider optimizing processes or scaling resources.",
                    "confidence": 0.85,
                    "action": "review_processes",
                    "server_id": server_id,
                    "related_data_id": data_id
                }))
            elif cpu_usage < 10:
                insights.append(await create_ai_insight({
                    "metric_type": "cpu_usage",
                    "insight_type": "optimization_opportunity",
                    "message": f"Low CPU usage: {cpu_usage}%. Server might be underutilized.",
                    "confidence": 0.75,
                    "action": "consider_consolidation",
                    "server_id": server_id,
                    "related_data_id": data_id
                }))
        
        # Analyze memory usage
        memory_usage = data.get('memory_usage')
        if memory_usage is not None and memory_usage > 90:
            insights.append(await create_ai_insight({
                "metric_type": "memory_usage",
                "insight_type": "resource_warning",
                "message": f"High memory usage: {memory_usage}%. Close unused applications or add more RAM.",
                "confidence": 0.80,
                "action": "increase_memory",
                "server_id": server_id,
                "related_data_id": data_id
            }))
        
        # Analyze disk usage
        disk_usage = data.get('disk_usage')
        if disk_usage is not None and disk_usage > 85:
            insights.append(await create_ai_insight({
                "metric_type": "disk_usage",
                "insight_type": "storage_alert",
                "message": f"High disk usage: {disk_usage}%. Consider cleaning up or expanding storage.",
                "confidence": 0.90,
                "action": "cleanup_storage",
                "server_id": server_id,
                "related_data_id": data_id
            }))
        
        # Analyze process count
        processes = data.get('processes', [])
        if len(processes) > 500:
            insights.append(await create_ai_insight({
                "metric_type": "process_count",
                "insight_type": "system_load",
                "message": f"High number of running processes: {len(processes)}. This may impact system performance.",
                "confidence": 0.70,
                "action": "review_processes",
                "server_id": server_id,
                "related_data_id": data_id
            }))
        
        return [insight for insight in insights if insight is not None]
        
    except Exception as e:
        logger.error(f"Error generating AI insights: {e}")
        return []

# ==================== USER ACTIVITY CRUD OPERATIONS ====================

async def log_user_activity(
    user_id: Optional[int] = None,
    username: str = "",
    activity_type: str = "login",
    ip_address: str = "",
    user_agent: str = "",
    success: bool = True,
    details: Optional[Dict] = None,
    session_id: str = None
) -> Optional[int]:
    """Log user activity for security monitoring"""
    try:
        query = """
        INSERT INTO user_activity (
            user_id, username, activity_type, ip_address, user_agent, 
            success, details, session_id, country, city, created_at
        )
        VALUES (
            :user_id, :username, :activity_type, :ip_address, :user_agent, 
            :success, :details, :session_id, :country, :city, CURRENT_TIMESTAMP
        )
        RETURNING id
        """
        values = {
            "user_id": user_id,
            "username": username,
            "activity_type": activity_type,
            "ip_address": ip_address,
            "user_agent": user_agent,
            "success": success,
            "details": json.dumps(details) if details else None,
            "session_id": session_id,
            "country": None,  # Could be populated from IP geolocation service
            "city": None
        }
        result = await database.fetch_one(query, values)
        activity_id = result["id"] if result else None
        
        # Check for suspicious activity patterns
        if activity_type == "login" and not success:
            await check_suspicious_login_activity(ip_address, username)
        
        return activity_id
    except Exception as e:
        logger.error(f"Error logging user activity: {e}")
        return None

async def check_suspicious_login_activity(ip_address: str, username: str):
    """Check for suspicious login patterns"""
    try:
        # Check for multiple failed logins from same IP
        query = """
        SELECT COUNT(*) as failed_attempts
        FROM user_activity 
        WHERE ip_address = :ip_address 
        AND activity_type = 'login' 
        AND success = false
        AND created_at >= (NOW() - INTERVAL '15 minutes')
        """
        result = await database.fetch_one(query, {"ip_address": ip_address})
        
        if result and result['failed_attempts'] >= 5:
            # Create security incident for brute force attempt
            await create_incident({
                "incident_type": "brute_force_attempt",
                "message": f"Multiple failed login attempts from IP {ip_address}",
                "severity": "high",
                "metadata": {
                    "ip_address": ip_address,
                    "failed_attempts": result['failed_attempts'],
                    "target_username": username,
                    "time_window": "15 minutes"
                }
            })
    except Exception as e:
        logger.error(f"Error checking suspicious login activity: {e}")

async def get_user_activities(
    user_id: Optional[int] = None,
    username: Optional[str] = None,
    activity_type: Optional[str] = None,
    ip_address: Optional[str] = None,
    success: Optional[bool] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    limit: int = 100,
    offset: int = 0
) -> List[Dict]:
    """Get user activities with filtering"""
    query = "SELECT * FROM user_activity WHERE 1=1"
    values = {"limit": limit, "offset": offset}
    
    if user_id is not None:
        query += " AND user_id = :user_id"
        values["user_id"] = user_id
    
    if username:
        query += " AND username = :username"
        values["username"] = username
        
    if activity_type:
        query += " AND activity_type = :activity_type"
        values["activity_type"] = activity_type
        
    if ip_address:
        query += " AND ip_address = :ip_address"
        values["ip_address"] = ip_address
        
    if success is not None:
        query += " AND success = :success"
        values["success"] = success
        
    if start_date:
        query += " AND created_at >= :start_date"
        values["start_date"] = start_date
        
    if end_date:
        query += " AND created_at <= :end_date"
        values["end_date"] = end_date
        
    query += " ORDER BY created_at DESC LIMIT :limit OFFSET :offset"
    
    results = await database.fetch_all(query, values)
    
    parsed_results = []
    for result in results:
        result_dict = dict(result)
        if 'details' in result_dict and result_dict['details'] and isinstance(result_dict['details'], str):
            try:
                result_dict['details'] = json.loads(result_dict['details'])
            except json.JSONDecodeError:
                result_dict['details'] = {}
        parsed_results.append(result_dict)
    
    return parsed_results

async def get_user_activity_stats(days: int = 30) -> List[Dict]:
    """Get user activity statistics - FIXED VERSION"""
    query = """
    SELECT activity_type, COUNT(*) AS count
    FROM user_activity
    WHERE created_at >= NOW() - (:days * INTERVAL '1 day')
    GROUP BY activity_type
    ORDER BY count DESC
    """
    return await database.fetch_all(query, {"days": days})

async def get_suspicious_activities(threshold_minutes: int = 5, failed_attempts: int = 3) -> List[Dict]:
    """Detect suspicious activities (multiple failed logins from same IP)"""
    query = """
    SELECT 
        ip_address,
        COUNT(*) as failed_attempts,
        MIN(created_at) as first_attempt,
        MAX(created_at) as last_attempt,
        STRING_AGG(DISTINCT username, ', ') as usernames
    FROM user_activity 
    WHERE activity_type = 'login' 
      AND success = false
      AND created_at >= (NOW() - (:threshold_minutes * INTERVAL '1 minute'))
    GROUP BY ip_address
    HAVING COUNT(*) >= :failed_attempts
    ORDER BY failed_attempts DESC
    """
    return await database.fetch_all(query, {
        "threshold_minutes": threshold_minutes,
        "failed_attempts": failed_attempts
    })

# ==================== VISITOR LOGS CRUD OPERATIONS ====================

async def log_visitor_request_fixed(
    ip_address: str,
    user_agent: str,
    request_method: str,
    request_path: str,
    request_query: Optional[Dict] = None,
    request_headers: Optional[Dict] = None,
    request_body: Optional[str] = None,
    response_status: int = 200,
    response_size: int = 0,
    processing_time: float = 0.0,
    suspicious: bool = False,
    suspicious_reason: Optional[str] = None,
    country: Optional[str] = None,
    city: Optional[str] = None,
    user_id: Optional[int] = None
) -> Optional[int]:
    """Log visitor request for security monitoring - FIXED VERSION with created_at"""
    try:
        # Check for suspicious patterns if not already marked
        if not suspicious:
            suspicious, suspicious_reason = await check_suspicious_request(
                ip_address, request_method, request_path, request_body, request_headers
            )
        
        query = """
        INSERT INTO visitor_logs (
            user_id, ip_address, user_agent, request_method, request_path,
            request_query, request_headers, request_body,
            response_status, response_size, processing_time,
            suspicious, suspicious_reason, country, city, created_at
        )
        VALUES (
            :user_id, :ip_address, :user_agent, :request_method, :request_path,
            :request_query, :request_headers, :request_body,
            :response_status, :response_size, :processing_time,
            :suspicious, :suspicious_reason, :country, :city, CURRENT_TIMESTAMP
        )
        RETURNING id
        """
        values = {
            "user_id": user_id,
            "ip_address": ip_address,
            "user_agent": user_agent,
            "request_method": request_method,
            "request_path": request_path,
            "request_query": json.dumps(request_query) if request_query else None,
            "request_headers": json.dumps(request_headers) if request_headers else None,
            "request_body": request_body,
            "response_status": response_status,
            "response_size": response_size,
            "processing_time": processing_time,
            "suspicious": suspicious,
            "suspicious_reason": suspicious_reason,
            "country": country,
            "city": city
        }
        result = await database.fetch_one(query, values)
        return result["id"] if result else None
    except Exception as e:
        logger.error(f"Error logging visitor request: {e}")
        return None

async def check_suspicious_request(
    ip_address: str, 
    method: str, 
    path: str, 
    body: Optional[str], 
    headers: Optional[Dict] = None
) -> tuple:
    """Check if request is suspicious"""
    suspicious = False
    reason = None
    
    # SQL injection patterns
    sql_patterns = [
        r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
        r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",
        r"\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))",
        r"((\%27)|(\'))union",
        r"exec(\s|\+)+(s|x)p\w+",
        r"insert(\s|\+)+into",
        r"drop(\s|\+)+table"
    ]
    
    # XSS patterns
    xss_patterns = [
        r"<script.*?>.*?</script>",
        r"javascript:",
        r"onload\s*=",
        r"onerror\s*=",
        r"onclick\s*=",
        r"<iframe.*?>.*?</iframe>",
        r"alert\s*\(",
        r"document\.cookie"
    ]
    
    # Path traversal
    path_traversal_patterns = [
        r"\.\./",
        r"\.\.\\",
        r"etc/passwd",
        r"win.ini",
        r"boot.ini",
        r"\.\.%2f"
    ]
    
    # Command injection patterns
    command_injection_patterns = [
        r"\|\|.*\b(bash|sh|cmd|powershell)\b",
        r"\b(rm|del|mkdir|echo)\s+-",
        r"\$\{.*\}",
        r"`.*`"
    ]
    
    all_patterns = sql_patterns + xss_patterns + path_traversal_patterns + command_injection_patterns
    
    # Check request body
    if body:
        body_lower = body.lower()
        for pattern in all_patterns:
            if re.search(pattern, body_lower, re.IGNORECASE):
                suspicious = True
                reason = "Potential injection attack detected in request body"
                break
    
    # Check request path
    path_lower = path.lower()
    for pattern in path_traversal_patterns + xss_patterns:
        if re.search(pattern, path_lower, re.IGNORECASE):
            suspicious = True
            reason = "Potential path traversal or XSS attempt"
            break
    
    # Check for excessive path length (potential buffer overflow)
    if len(path) > 500:
        suspicious = True
        reason = "Excessively long request path"
    
    # Check for suspicious user agents
    if headers and 'user-agent' in headers:
        user_agent = headers['user-agent'].lower()
        suspicious_agents = ['sqlmap', 'nikto', 'metasploit', 'nmap', 'burpsuite']
        if any(agent in user_agent for agent in suspicious_agents):
            suspicious = True
            reason = "Suspicious security scanner detected"
    
    return suspicious, reason

async def get_visitor_logs(
    ip_address: Optional[str] = None,
    request_method: Optional[str] = None,
    request_path: Optional[str] = None,
    suspicious: Optional[bool] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    limit: int = 100,
    offset: int = 0
) -> List[Dict]:
    """Get visitor logs with filtering"""
    query = "SELECT * FROM visitor_logs WHERE 1=1"
    values = {"limit": limit, "offset": offset}
    
    if ip_address:
        query += " AND ip_address = :ip_address"
        values["ip_address"] = ip_address
        
    if request_method:
        query += " AND request_method = :request_method"
        values["request_method"] = request_method
        
    if request_path:
        query += " AND request_path LIKE :request_path"
        values["request_path"] = f"%{request_path}%"
        
    if suspicious is not None:
        query += " AND suspicious = :suspicious"
        values["suspicious"] = suspicious
        
    if start_date:
        query += " AND created_at >= :start_date"
        values["start_date"] = start_date
        
    if end_date:
        query += " AND created_at <= :end_date"
        values["end_date"] = end_date
        
    query += " ORDER BY created_at DESC LIMIT :limit OFFSET :offset"
    
    results = await database.fetch_all(query, values)
    
    parsed_results = []
    for result in results:
        result_dict = dict(result)
        for field in ['request_query', 'request_headers']:
            if result_dict.get(field) and isinstance(result_dict[field], str):
                try:
                    result_dict[field] = json.loads(result_dict[field])
                except json.JSONDecodeError:
                    result_dict[field] = {}
        parsed_results.append(result_dict)
    
    return parsed_results

async def get_visitor_stats(days: int = 7) -> Dict:
    """Get comprehensive visitor statistics"""
    stats_queries = {
        "total_requests": """
        SELECT COUNT(*) as count FROM visitor_logs 
        WHERE created_at >= (NOW() - (:days * INTERVAL '1 day'))
        """,
        "suspicious_requests": """
        SELECT COUNT(*) as count FROM visitor_logs 
        WHERE suspicious = true AND created_at >= (NOW() - (:days * INTERVAL '1 day'))
        """,
        "unique_visitors": """
        SELECT COUNT(DISTINCT ip_address) as count FROM visitor_logs 
        WHERE created_at >= (NOW() - (:days * INTERVAL '1 day'))
        """,
        "top_ips": """
        SELECT ip_address, COUNT(*) as request_count, MAX(created_at) as last_seen
        FROM visitor_logs 
        WHERE created_at >= (NOW() - (:days * INTERVAL '1 day'))
        GROUP BY ip_address 
        ORDER BY request_count DESC 
        LIMIT 10
        """,
        "requests_by_method": """
        SELECT request_method, COUNT(*) as count
        FROM visitor_logs 
        WHERE created_at >= (NOW() - (:days * INTERVAL '1 day'))
        GROUP BY request_method
        ORDER BY count DESC
        """,
        "requests_by_status": """
        SELECT response_status, COUNT(*) as count
        FROM visitor_logs 
        WHERE created_at >= (NOW() - (:days * INTERVAL '1 day'))
        GROUP BY response_status
        ORDER BY count DESC
        """,
        "suspicious_ips": """
        SELECT ip_address, COUNT(*) as suspicious_count
        FROM visitor_logs 
        WHERE suspicious = true AND created_at >= (NOW() - (:days * INTERVAL '1 day'))
        GROUP BY ip_address
        ORDER BY suspicious_count DESC
        LIMIT 10
        """
    }
    
    stats = {}
    for key, query in stats_queries.items():
        if key in ["top_ips", "requests_by_method", "requests_by_status", "suspicious_ips"]:
            stats[key] = await database.fetch_all(query, {"days": days})
        else:
            result = await database.fetch_one(query, {"days": days})
            stats[key] = result["count"] if result else 0
    
    return stats

async def cleanup_old_visitor_logs(days: int = 90) -> int:
    """Clean up visitor logs older than specified days"""
    try:
        query = """
        DELETE FROM visitor_logs 
        WHERE created_at < (NOW() - (:days * INTERVAL '1 day'))
        """
        result = await database.execute(query, {"days": days})
        logger.info(f"Cleaned up {result} old visitor logs older than {days} days")
        return result
    except Exception as e:
        logger.error(f"Error cleaning up old visitor logs: {e}")
        return 0

# ==================== ALERT RULES CRUD ====================

async def create_alert_rule(alert_rule: dict, user_id: int) -> Optional[Dict]:
    """Create a new alert rule"""
    try:
        query = """
        INSERT INTO alert_rules (
            server_id, metric, threshold_value, comparison_operator, 
            severity, active, description, created_by, 
            duration_threshold, cooldown_period, tags,
            created_at, updated_at
        )
        VALUES (
            :server_id, :metric, :threshold_value, :comparison_operator, 
            :severity, :active, :description, :created_by,
            :duration_threshold, :cooldown_period, :tags,
            CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
        )
        RETURNING *
        """
        values = {
            **alert_rule,
            "created_by": user_id,
            "duration_threshold": alert_rule.get("duration_threshold", 0),
            "cooldown_period": alert_rule.get("cooldown_period", 300),
            "tags": json.dumps(alert_rule.get("tags", []))
        }
        result = await database.fetch_one(query, values)
        
        if result:
            result_dict = dict(result)
            if result_dict.get('tags') and isinstance(result_dict['tags'], str):
                try:
                    result_dict['tags'] = json.loads(result_dict['tags'])
                except json.JSONDecodeError:
                    result_dict['tags'] = []
            return result_dict
        return None
    except Exception as e:
        logger.error(f"Error creating alert rule: {e}")
        return None

async def get_alert_rules(
    active_only: bool = True, 
    server_id: Optional[int] = None,
    metric: Optional[str] = None,
    severity: Optional[str] = None
) -> List[Dict]:
    """Get alert rules with filtering"""
    query = "SELECT * FROM alert_rules WHERE 1=1"
    values = {}
    
    if active_only:
        query += " AND active = true"
    
    if server_id is not None:
        query += " AND (server_id = :server_id OR server_id IS NULL)"
        values["server_id"] = server_id
    
    if metric:
        query += " AND metric = :metric"
        values["metric"] = metric
        
    if severity:
        query += " AND severity = :severity"
        values["severity"] = severity
    
    query += " ORDER BY created_at DESC"
    results = await database.fetch_all(query, values)
    
    processed_results = []
    for result in results:
        result_dict = dict(result)
        if result_dict.get('tags') and isinstance(result_dict['tags'], str):
            try:
                result_dict['tags'] = json.loads(result_dict['tags'])
            except json.JSONDecodeError:
                result_dict['tags'] = []
        processed_results.append(result_dict)
    
    return processed_results

async def get_alert_rule(rule_id: int) -> Optional[Dict]:
    """Get alert rule by ID"""
    query = "SELECT * FROM alert_rules WHERE id = :id"
    result = await database.fetch_one(query, {"id": rule_id})
    if result:
        result_dict = dict(result)
        if result_dict.get('tags') and isinstance(result_dict['tags'], str):
            try:
                result_dict['tags'] = json.loads(result_dict['tags'])
            except json.JSONDecodeError:
                result_dict['tags'] = []
        return result_dict
    return None

async def update_alert_rule(rule_id: int, alert_rule: dict) -> Optional[Dict]:
    """Update alert rule"""
    try:
        query = """
        UPDATE alert_rules 
        SET server_id = :server_id, 
            metric = :metric, 
            threshold_value = :threshold_value, 
            comparison_operator = :comparison_operator, 
            severity = :severity, 
            active = :active, 
            description = :description, 
            duration_threshold = :duration_threshold,
            cooldown_period = :cooldown_period,
            tags = :tags,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = :id
        RETURNING *
        """
        values = {
            **alert_rule,
            "id": rule_id,
            "tags": json.dumps(alert_rule.get("tags", []))
        }
        result = await database.fetch_one(query, values)
        if result:
            result_dict = dict(result)
            if result_dict.get('tags') and isinstance(result_dict['tags'], str):
                try:
                    result_dict['tags'] = json.loads(result_dict['tags'])
                except json.JSONDecodeError:
                    result_dict['tags'] = []
            return result_dict
        return None
    except Exception as e:
        logger.error(f"Error updating alert rule {rule_id}: {e}")
        return None

async def delete_alert_rule(rule_id: int) -> bool:
    """Delete alert rule"""
    try:
        query = "DELETE FROM alert_rules WHERE id = :id"
        result = await database.execute(query, {"id": rule_id})
        return result > 0
    except Exception as e:
        logger.error(f"Error deleting alert rule {rule_id}: {e}")
        return False

async def toggle_alert_rule(rule_id: int, active: bool) -> Optional[Dict]:
    """Toggle alert rule active status"""
    try:
        query = """
        UPDATE alert_rules 
        SET active = :active, updated_at = CURRENT_TIMESTAMP 
        WHERE id = :id 
        RETURNING *
        """
        result = await database.fetch_one(query, {"active": active, "id": rule_id})
        if result:
            result_dict = dict(result)
            if result_dict.get('tags') and isinstance(result_dict['tags'], str):
                try:
                    result_dict['tags'] = json.loads(result_dict['tags'])
                except json.JSONDecodeError:
                    result_dict['tags'] = []
            return result_dict
        return None
    except Exception as e:
        logger.error(f"Error toggling alert rule {rule_id}: {e}")
        return None

# ==================== INCIDENTS CRUD ====================

async def create_incident(incident: dict) -> Optional[int]:
    """Create a new incident"""
    try:
        query = """
        INSERT INTO incidents (
            server_id, alert_rule_id, agent_data_id, incident_type, 
            message, severity, metadata, status, created_at
        )
        VALUES (
            :server_id, :alert_rule_id, :agent_data_id, :incident_type, 
            :message, :severity, :metadata, :status, CURRENT_TIMESTAMP
        )
        RETURNING id
        """
        
        values = {
            "server_id": incident.get("server_id"),
            "alert_rule_id": incident.get("alert_rule_id"),
            "agent_data_id": incident.get("agent_data_id"),
            "incident_type": incident["incident_type"],
            "message": incident["message"],
            "severity": incident["severity"],
            "metadata": json.dumps(incident.get("metadata", {})),
            "status": incident.get("status", "open")
        }
        
        result = await database.fetch_one(query, values)
        incident_id = result["id"] if result else None
        
        if incident_id:
            logger.info(f"Created incident {incident_id}: {incident['incident_type']} - {incident['message']}")
            
            # Send notifications for high severity incidents
            if incident["severity"] in ["high", "critical"]:
                await create_notification({
                    "type": "incident",
                    "title": f"New {incident['severity']} severity incident",
                    "message": incident["message"],
                    "related_id": incident_id,
                    "priority": "high"
                })
        
        return incident_id
    except Exception as e:
        logger.error(f"Error creating incident: {e}")
        return None

async def get_incidents(
    status: str = None, 
    severity: str = None, 
    server_id: Optional[int] = None,
    incident_type: Optional[str] = None,
    limit: int = 100, 
    offset: int = 0
) -> List[Dict]:
    """Get incidents with filtering"""
    query = """
    SELECT i.*, s.hostname as server_hostname, ar.description as rule_description
    FROM incidents i
    LEFT JOIN servers s ON i.server_id = s.id
    LEFT JOIN alert_rules ar ON i.alert_rule_id = ar.id
    WHERE 1=1
    """
    values = {"limit": limit, "offset": offset}
    
    if status:
        query += " AND i.status = :status"
        values["status"] = status
    
    if severity:
        query += " AND i.severity = :severity"
        values["severity"] = severity
        
    if server_id is not None:
        query += " AND (i.server_id = :server_id OR i.server_id IS NULL)"
        values["server_id"] = server_id
        
    if incident_type:
        query += " AND i.incident_type = :incident_type"
        values["incident_type"] = incident_type
        
    query += " ORDER BY i.created_at DESC LIMIT :limit OFFSET :offset"
    
    results = await database.fetch_all(query, values)
    
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

async def get_incident(incident_id: int) -> Optional[Dict]:
    """Get incident by ID"""
    query = """
    SELECT i.*, s.hostname as server_hostname, ar.description as rule_description
    FROM incidents i
    LEFT JOIN servers s ON i.server_id = s.id
    LEFT JOIN alert_rules ar ON i.alert_rule_id = ar.id
    WHERE i.id = :id
    """
    result = await database.fetch_one(query, {"id": incident_id})
    if result:
        result_dict = dict(result)
        if 'metadata' in result_dict and result_dict['metadata'] and isinstance(result_dict['metadata'], str):
            try:
                result_dict['metadata'] = json.loads(result_dict['metadata'])
            except json.JSONDecodeError:
                result_dict['metadata'] = {}
        return result_dict
    return None

async def update_incident_status(
    incident_id: int, 
    status: str, 
    user_id: int = None, 
    notes: str = None
) -> Optional[Dict]:
    """Update incident status"""
    try:
        query = """
        UPDATE incidents 
        SET status = :status, 
            acknowledged_by = CASE WHEN :status = 'acknowledged' AND acknowledged_by IS NULL THEN :user_id ELSE acknowledged_by END,
            acknowledged_at = CASE WHEN :status = 'acknowledged' AND acknowledged_at IS NULL THEN CURRENT_TIMESTAMP ELSE acknowledged_at END,
            resolved_by = CASE WHEN :status IN ('resolved', 'closed') THEN :user_id ELSE resolved_by END,
            resolved_at = CASE WHEN :status IN ('resolved', 'closed') THEN CURRENT_TIMESTAMP ELSE resolved_at END,
            resolved_notes = COALESCE(:notes, resolved_notes),
            updated_at = CURRENT_TIMESTAMP
        WHERE id = :id
        RETURNING *
        """
        result = await database.fetch_one(query, {
            "id": incident_id, 
            "status": status, 
            "user_id": user_id, 
            "notes": notes
        })
        
        if result:
            result_dict = dict(result)
            if 'metadata' in result_dict and result_dict['metadata'] and isinstance(result_dict['metadata'], str):
                try:
                    result_dict['metadata'] = json.loads(result_dict['metadata'])
                except json.JSONDecodeError:
                    result_dict['metadata'] = {}
            return result_dict
        return None
    except Exception as e:
        logger.error(f"Error updating incident status {incident_id}: {e}")
        return None

async def add_incident_comment(incident_id: int, user_id: int, comment: str) -> bool:
    """Add comment to incident"""
    try:
        # Get existing comments
        incident = await get_incident(incident_id)
        if not incident:
            return False
            
        existing_comments = incident.get('comments', [])
        if isinstance(existing_comments, str):
            try:
                existing_comments = json.loads(existing_comments)
            except json.JSONDecodeError:
                existing_comments = []
        
        # Add new comment
        new_comment = {
            "user_id": user_id,
            "comment": comment,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        existing_comments.append(new_comment)
        
        query = """
        UPDATE incidents 
        SET comments = :comments,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = :id
        """
        
        result = await database.execute(query, {
            "id": incident_id,
            "comments": json.dumps(existing_comments)
        })
        return result > 0
    except Exception as e:
        logger.error(f"Error adding comment to incident {incident_id}: {e}")
        return False

async def get_incident_stats(server_id: Optional[int] = None) -> List[Dict]:
    """Get incident statistics"""
    query = """
    SELECT 
        status,
        severity,
        COUNT(*) as count
    FROM incidents 
    WHERE (:server_id IS NULL OR server_id = :server_id)
    GROUP BY status, severity
    ORDER BY status, severity
    """
    return await database.fetch_all(query, {"server_id": server_id})

async def get_incidents_count(
    status: str = None, 
    server_id: Optional[int] = None,
    severity: str = None
) -> int:
    """Get count of incidents with filtering"""
    query = "SELECT COUNT(*) as count FROM incidents WHERE 1=1"
    values = {}
    if status:
        query += " AND status = :status"
        values["status"] = status
    if server_id is not None:
        query += " AND (server_id = :server_id OR server_id IS NULL)"
        values["server_id"] = server_id
    if severity:
        query += " AND severity = :severity"
        values["severity"] = severity
        
    result = await database.fetch_one(query, values)
    return result["count"] if result else 0

async def get_recent_incidents(
    hours: int = 24, 
    server_id: Optional[int] = None,
    severity: str = None
) -> List[Dict]:
    """Get recent incidents"""
    query = """
    SELECT i.*, s.hostname as server_hostname
    FROM incidents i
    LEFT JOIN servers s ON i.server_id = s.id
    WHERE i.created_at >= (NOW() - (:hours * INTERVAL '1 hour'))
    AND (:server_id IS NULL OR i.server_id = :server_id)
    """
    values = {"hours": hours, "server_id": server_id}
    
    if severity:
        query += " AND i.severity = :severity"
        values["severity"] = severity
        
    query += " ORDER BY i.created_at DESC"
    
    results = await database.fetch_all(query, values)
    
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

# ==================== DASHBOARD LAYOUTS CRUD ====================

async def create_dashboard_layout(
    user_id: int, 
    name: str, 
    layout: dict = None, 
    widgets: dict = None, 
    filters: dict = None,
    is_default: bool = False
) -> Optional[int]:
    """Create a new dashboard layout"""
    try:
        # If setting as default, remove default from other layouts
        if is_default:
            await database.execute(
                "UPDATE user_dashboard_layouts SET is_default = FALSE WHERE user_id = :user_id",
                {"user_id": user_id}
            )
        
        query = """
        INSERT INTO user_dashboard_layouts (user_id, name, layout, widgets, filters, is_default)
        VALUES (:user_id, :name, :layout, :widgets, :filters, :is_default)
        RETURNING id
        """
        values = {
            "user_id": user_id,
            "name": name,
            "layout": json.dumps(layout) if layout else None,
            "widgets": json.dumps(widgets) if widgets else None,
            "filters": json.dumps(filters) if filters else None,
            "is_default": is_default
        }
        
        result = await database.fetch_one(query, values)
        return result["id"] if result else None
    except Exception as e:
        logger.error(f"Error creating dashboard layout: {e}")
        return None

async def get_user_dashboard_layouts(user_id: int) -> List[Dict]:
    """Get all dashboard layouts for a user"""
    query = "SELECT * FROM user_dashboard_layouts WHERE user_id = :user_id ORDER BY created_at DESC"
    results = await database.fetch_all(query, {"user_id": user_id})
    
    layouts = []
    for result in results:
        layout_dict = dict(result)
        for field in ['layout', 'widgets', 'filters']:
            if layout_dict.get(field) and isinstance(layout_dict[field], str):
                try:
                    layout_dict[field] = json.loads(layout_dict[field])
                except json.JSONDecodeError:
                    layout_dict[field] = {}
        layouts.append(layout_dict)
    
    return layouts

async def get_dashboard_layout(layout_id: int, user_id: int) -> Optional[Dict]:
    """Get specific dashboard layout"""
    query = "SELECT * FROM user_dashboard_layouts WHERE id = :layout_id AND user_id = :user_id"
    result = await database.fetch_one(query, {"layout_id": layout_id, "user_id": user_id})
    
    if result:
        layout_dict = dict(result)
        for field in ['layout', 'widgets', 'filters']:
            if layout_dict.get(field) and isinstance(layout_dict[field], str):
                try:
                    layout_dict[field] = json.loads(layout_dict[field])
                except json.JSONDecodeError:
                    layout_dict[field] = {}
        return layout_dict
    
    return None

async def update_dashboard_layout(
    layout_id: int, 
    user_id: int, 
    name: str = None, 
    layout: dict = None, 
    widgets: dict = None, 
    filters: dict = None
) -> Optional[Dict]:
    """Update dashboard layout"""
    update_fields = []
    params = {"layout_id": layout_id, "user_id": user_id}
    
    if name is not None:
        update_fields.append("name = :name")
        params["name"] = name
    
    if layout is not None:
        update_fields.append("layout = :layout")
        params["layout"] = json.dumps(layout)
    
    if widgets is not None:
        update_fields.append("widgets = :widgets")
        params["widgets"] = json.dumps(widgets)
    
    if filters is not None:
        update_fields.append("filters = :filters")
        params["filters"] = json.dumps(filters)
    
    if update_fields:
        update_fields.append("updated_at = CURRENT_TIMESTAMP")
        query = f"UPDATE user_dashboard_layouts SET {', '.join(update_fields)} WHERE id = :layout_id AND user_id = :user_id RETURNING *"
        result = await database.fetch_one(query, params)
        
        if result:
            result_dict = dict(result)
            for field in ['layout', 'widgets', 'filters']:
                if result_dict.get(field) and isinstance(result_dict[field], str):
                    try:
                        result_dict['field'] = json.loads(result_dict['field'])
                    except json.JSONDecodeError:
                        result_dict['field'] = {}
            return result_dict
    
    return await get_dashboard_layout(layout_id, user_id)

async def delete_dashboard_layout(layout_id: int, user_id: int) -> bool:
    """Delete dashboard layout"""
    try:
        query = "DELETE FROM user_dashboard_layouts WHERE id = :layout_id AND user_id = :user_id"
        result = await database.execute(query, {"layout_id": layout_id, "user_id": user_id})
        return result > 0
    except Exception as e:
        logger.error(f"Error deleting dashboard layout {layout_id}: {e}")
        return False

async def set_default_layout(layout_id: int, user_id: int) -> bool:
    """Set a layout as default for user"""
    try:
        await database.execute(
            "UPDATE user_dashboard_layouts SET is_default = FALSE WHERE user_id = :user_id",
            {"user_id": user_id}
        )
        
        result = await database.execute(
            "UPDATE user_dashboard_layouts SET is_default = TRUE WHERE id = :layout_id AND user_id = :user_id",
            {"layout_id": layout_id, "user_id": user_id}
        )
        return result > 0
    except Exception as e:
        logger.error(f"Error setting default layout: {e}")
        return False

async def get_default_layout(user_id: int) -> Optional[Dict]:
    """Get user's default dashboard layout"""
    query = "SELECT * FROM user_dashboard_layouts WHERE user_id = :user_id AND is_default = TRUE"
    result = await database.fetch_one(query, {"user_id": user_id})
    
    if result:
        layout_dict = dict(result)
        for field in ['layout', 'widgets', 'filters']:
            if layout_dict.get(field) and isinstance(layout_dict[field], str):
                try:
                    layout_dict[field] = json.loads(layout_dict[field])
                except json.JSONDecodeError:
                    layout_dict[field] = {}
        return layout_dict
    
    return None

# ==================== AI INSIGHTS CRUD OPERATIONS ====================

async def create_ai_insight(insight_data: dict) -> Optional[int]:
    """Create a new AI insight"""
    try:
        query = """
        INSERT INTO ai_insights (
            metric_type, insight_type, message, confidence, 
            action, server_id, related_data_id, metadata, created_at
        )
        VALUES (
            :metric_type, :insight_type, :message, :confidence, 
            :action, :server_id, :related_data_id, :metadata, CURRENT_TIMESTAMP
        )
        RETURNING id
        """
        values = {
            "metric_type": insight_data["metric_type"],
            "insight_type": insight_data["insight_type"],
            "message": insight_data["message"],
            "confidence": insight_data["confidence"],
            "action": insight_data.get("action"),
            "server_id": insight_data.get("server_id"),
            "related_data_id": insight_data.get("related_data_id"),
            "metadata": json.dumps(insight_data.get("metadata", {}))
        }
        result = await database.fetch_one(query, values)
        insight_id = result["id"] if result else None
        
        if insight_id and insight_data.get("confidence", 0) > 0.8:
            # Create notification for high-confidence insights
            await create_notification({
                "type": "ai_insight",
                "title": f"AI Insight: {insight_data['insight_type']}",
                "message": insight_data["message"],
                "related_id": insight_id,
                "priority": "medium"
            })
        
        return insight_id
    except Exception as e:
        logger.error(f"Error creating AI insight: {e}")
        return None

async def get_ai_insights(
    server_id: Optional[int] = None,
    insight_type: Optional[str] = None,
    metric_type: Optional[str] = None,
    limit: int = 50,
    min_confidence: float = 0.0
) -> List[Dict]:
    """Get AI insights with filtering"""
    query = """
    SELECT ai.*, s.hostname as server_hostname
    FROM ai_insights ai
    LEFT JOIN servers s ON ai.server_id = s.id
    WHERE 1=1
    """
    values = {"limit": limit, "min_confidence": min_confidence}
    
    if server_id is not None:
        query += " AND (ai.server_id = :server_id OR ai.server_id IS NULL)"
        values["server_id"] = server_id
        
    if insight_type:
        query += " AND ai.insight_type = :insight_type"
        values["insight_type"] = insight_type
        
    if metric_type:
        query += " AND ai.metric_type = :metric_type"
        values["metric_type"] = metric_type
        
    query += " AND ai.confidence >= :min_confidence"
    query += " ORDER BY ai.created_at DESC LIMIT :limit"
    
    results = await database.fetch_all(query, values)
    
    insights = []
    for result in results:
        insight_dict = dict(result)
        if insight_dict.get('metadata') and isinstance(insight_dict['metadata'], str):
            try:
                insight_dict['metadata'] = json.loads(insight_dict['metadata'])
            except json.JSONDecodeError:
                insight_dict['metadata'] = {}
        insights.append(insight_dict)
    
    return insights

async def get_recent_ai_insights(limit: int = 10, min_confidence: float = 0.7) -> List[Dict]:
    """Get recent AI insights with minimum confidence"""
    query = """
    SELECT ai.*, s.hostname as server_hostname
    FROM ai_insights ai
    LEFT JOIN servers s ON ai.server_id = s.id
    WHERE ai.confidence >= :min_confidence
    ORDER BY ai.created_at DESC 
    LIMIT :limit
    """
    return await database.fetch_all(query, {"limit": limit, "min_confidence": min_confidence})

async def get_ai_insight_stats(days: int = 7) -> Dict:
    """Get AI insight statistics"""
    query = """
    SELECT 
        insight_type,
        COUNT(*) as total_insights,
        AVG(confidence) as avg_confidence,
        COUNT(CASE WHEN confidence > 0.8 THEN 1 END) as high_confidence_insights
    FROM ai_insights 
    WHERE created_at >= (NOW() - (:days * INTERVAL '1 day'))
    GROUP BY insight_type
    ORDER BY total_insights DESC
    """
    results = await database.fetch_all(query, {"days": days})
    
    stats = {
        "by_insight_type": results,
        "total_insights": sum(row['total_insights'] for row in results),
        "avg_confidence": sum(row['avg_confidence'] for row in results) / len(results) if results else 0
    }
    
    return stats

# ==================== AI FEEDBACK CRUD OPERATIONS ====================

async def store_ai_feedback(
    user_id: int,
    alert_id: Optional[int] = None,
    incident_id: Optional[int] = None,
    prediction_type: str = "anomaly",
    was_correct: bool = True,
    user_comment: Optional[str] = None,
    metrics_snapshot: Optional[Dict[str, Any]] = None
) -> Optional[int]:
    """
    Store AI prediction feedback from users
    """
    try:
        query = """
        INSERT INTO ai_feedback 
        (user_id, alert_id, incident_id, prediction_type, was_correct, user_comment, metrics_snapshot, created_at)
        VALUES (:user_id, :alert_id, :incident_id, :prediction_type, :was_correct, :user_comment, :metrics_snapshot, CURRENT_TIMESTAMP)
        RETURNING id
        """
        
        values = {
            "user_id": user_id,
            "alert_id": alert_id,
            "incident_id": incident_id,
            "prediction_type": prediction_type,
            "was_correct": was_correct,
            "user_comment": user_comment,
            "metrics_snapshot": json.dumps(metrics_snapshot) if metrics_snapshot else None
        }
        
        result = await database.fetch_one(query, values)
        return result["id"] if result else None
        
    except Exception as e:
        logger.error(f"Error storing AI feedback: {e}")
        return None

async def get_ai_feedback(
    user_id: Optional[int] = None,
    prediction_type: Optional[str] = None,
    limit: int = 100,
    offset: int = 0
) -> List[Dict]:
    """
    Get AI feedback data
    """
    try:
        query = "SELECT * FROM ai_feedback WHERE 1=1"
        params = {}
        
        if user_id is not None:
            query += " AND user_id = :user_id"
            params["user_id"] = user_id
            
        if prediction_type is not None:
            query += " AND prediction_type = :prediction_type"
            params["prediction_type"] = prediction_type
            
        query += " ORDER BY created_at DESC LIMIT :limit OFFSET :offset"
        params["limit"] = limit
        params["offset"] = offset
        
        results = await database.fetch_all(query, params)
        
        feedback_list = []
        for result in results:
            result_dict = dict(result)
            # Parse metrics_snapshot if it exists
            if result_dict.get('metrics_snapshot') and isinstance(result_dict['metrics_snapshot'], str):
                try:
                    result_dict['metrics_snapshot'] = json.loads(result_dict['metrics_snapshot'])
                except json.JSONDecodeError:
                    result_dict['metrics_snapshot'] = {}
            feedback_list.append(result_dict)
            
        return feedback_list
        
    except Exception as e:
        logger.error(f"Error getting AI feedback: {e}")
        return []

async def get_ai_feedback_stats(days: int = 30) -> Dict:
    """Get AI feedback statistics"""
    query = """
    SELECT 
        prediction_type,
        was_correct,
        COUNT(*) as count,
        AVG(CASE WHEN was_correct THEN 1.0 ELSE 0.0 END) as accuracy_rate
    FROM ai_feedback 
    WHERE created_at >= (NOW() - (:days * INTERVAL '1 day'))
    GROUP BY prediction_type, was_correct
    ORDER BY prediction_type, was_correct
    """
    results = await database.fetch_all(query, {"days": days})
    
    stats = {
        "by_prediction_type": results,
        "total_feedback": sum(row['count'] for row in results),
        "overall_accuracy": sum(row['count'] * (1.0 if row['was_correct'] else 0.0) for row in results) / sum(row['count'] for row in results) if results else 0
    }
    
    return stats

# ==================== NOTIFICATIONS CRUD ====================

async def create_notification(notification_data: dict) -> Optional[int]:
    """Create a new notification"""
    try:
        query = """
        INSERT INTO notifications (
            type, title, message, priority, related_id, 
            metadata, created_at
        )
        VALUES (
            :type, :title, :message, :priority, :related_id,
            :metadata, CURRENT_TIMESTAMP
        )
        RETURNING id
        """
        values = {
            "type": notification_data["type"],
            "title": notification_data["title"],
            "message": notification_data["message"],
            "priority": notification_data.get("priority", "medium"),
            "related_id": notification_data.get("related_id"),
            "metadata": json.dumps(notification_data.get("metadata", {}))
        }
        result = await database.fetch_one(query, values)
        return result["id"] if result else None
    except Exception as e:
        logger.error(f"Error creating notification: {e}")
        return None

async def get_notifications(
    read: bool = None,
    priority: str = None,
    type: str = None,
    limit: int = 50,
    offset: int = 0
) -> List[Dict]:
    """Get notifications with filtering"""
    query = "SELECT * FROM notifications WHERE 1=1"
    values = {"limit": limit, "offset": offset}
    
    if read is not None:
        query += " AND read = :read"
        values["read"] = read
        
    if priority:
        query += " AND priority = :priority"
        values["priority"] = priority
        
    if type:
        query += " AND type = :type"
        values["type"] = type
        
    query += " ORDER BY created_at DESC LIMIT :limit OFFSET :offset"
    
    results = await database.fetch_all(query, values)
    
    notifications = []
    for result in results:
        notification_dict = dict(result)
        if notification_dict.get('metadata') and isinstance(notification_dict['metadata'], str):
            try:
                notification_dict['metadata'] = json.loads(notification_dict['metadata'])
            except json.JSONDecodeError:
                notification_dict['metadata'] = {}
        notifications.append(notification_dict)
    
    return notifications

async def mark_notification_read(notification_id: int) -> bool:
    """Mark notification as read"""
    try:
        query = "UPDATE notifications SET read = true, read_at = CURRENT_TIMESTAMP WHERE id = :id"
        result = await database.execute(query, {"id": notification_id})
        return result > 0
    except Exception as e:
        logger.error(f"Error marking notification {notification_id} as read: {e}")
        return False

async def mark_all_notifications_read() -> int:
    """Mark all notifications as read"""
    try:
        query = "UPDATE notifications SET read = true, read_at = CURRENT_TIMESTAMP WHERE read = false"
        result = await database.execute(query)
        return result
    except Exception as e:
        logger.error(f"Error marking all notifications as read: {e}")
        return 0

async def get_unread_notifications_count() -> int:
    """Get count of unread notifications"""
    query = "SELECT COUNT(*) as count FROM notifications WHERE read = false"
    result = await database.fetch_one(query)
    return result["count"] if result else 0

# ==================== SERVER LOCATIONS CRUD OPERATIONS ====================

async def create_server_location(location_data: dict) -> Optional[int]:
    """Create a new server location"""
    try:
        query = """
        INSERT INTO server_locations (
            name, latitude, longitude, status, current_load, 
            active_users, server_id, description, tags, last_updated
        )
        VALUES (
            :name, :latitude, :longitude, :status, :current_load, 
            :active_users, :server_id, :description, :tags, CURRENT_TIMESTAMP
        )
        RETURNING id
        """
        values = {
            "name": location_data["name"],
            "latitude": location_data["latitude"],
            "longitude": location_data["longitude"],
            "status": location_data.get("status", "online"),
            "current_load": location_data.get("current_load", 0.0),
            "active_users": location_data.get("active_users", 0),
            "server_id": location_data.get("server_id"),
            "description": location_data.get("description", ""),
            "tags": json.dumps(location_data.get("tags", []))
        }
        result = await database.fetch_one(query, values)
        return result["id"] if result else None
    except Exception as e:
        logger.error(f"Error creating server location: {e}")
        return None

async def get_server_locations(server_id: Optional[int] = None, status: str = None) -> List[Dict]:
    """Get all server locations with optional filtering"""
    query = "SELECT * FROM server_locations WHERE 1=1"
    values = {}
    
    if server_id is not None:
        query += " AND server_id = :server_id"
        values["server_id"] = server_id
        
    if status:
        query += " AND status = :status"
        values["status"] = status
        
    query += " ORDER BY name"
    
    results = await database.fetch_all(query, values)
    
    locations = []
    for result in results:
        location_dict = dict(result)
        if location_dict.get('tags') and isinstance(location_dict['tags'], str):
            try:
                location_dict['tags'] = json.loads(location_dict['tags'])
            except json.JSONDecodeError:
                location_dict['tags'] = []
        locations.append(location_dict)
    
    return locations

async def get_server_location_by_id(location_id: int) -> Optional[Dict]:
    """Get server location by ID"""
    query = """
    SELECT sl.*, s.hostname as server_hostname
    FROM server_locations sl
    LEFT JOIN servers s ON sl.server_id = s.id
    WHERE sl.id = :id
    """
    result = await database.fetch_one(query, {"id": location_id})
    if result:
        location_dict = dict(result)
        if location_dict.get('tags') and isinstance(location_dict['tags'], str):
            try:
                location_dict['tags'] = json.loads(location_dict['tags'])
            except json.JSONDecodeError:
                location_dict['tags'] = []
        return location_dict
    return None

async def update_server_location(location_id: int, location_data: dict) -> Optional[Dict]:
    """Update server location"""
    try:
        query = """
        UPDATE server_locations 
        SET name = :name, 
            latitude = :latitude, 
            longitude = :longitude, 
            status = :status, 
            current_load = :current_load, 
            active_users = :active_users,
            server_id = :server_id,
            description = :description,
            tags = :tags,
            last_updated = CURRENT_TIMESTAMP
        WHERE id = :id
        RETURNING *
        """
        values = {
            "id": location_id,
            "name": location_data["name"],
            "latitude": location_data["latitude"],
            "longitude": location_data["longitude"],
            "status": location_data.get("status", "online"),
            "current_load": location_data.get("current_load", 0.0),
            "active_users": location_data.get("active_users", 0),
            "server_id": location_data.get("server_id"),
            "description": location_data.get("description", ""),
            "tags": json.dumps(location_data.get("tags", []))
        }
        result = await database.fetch_one(query, values)
        
        if result:
            location_dict = dict(result)
            if location_dict.get('tags') and isinstance(location_dict['tags'], str):
                try:
                    location_dict['tags'] = json.loads(location_dict['tags'])
                except json.JSONDecodeError:
                    location_dict['tags'] = []
            return location_dict
        return None
    except Exception as e:
        logger.error(f"Error updating server location: {e}")
        return None

async def delete_server_location(location_id: int) -> bool:
    """Delete a server location"""
    try:
        query = "DELETE FROM server_locations WHERE id = :location_id"
        result = await database.execute(query, {"location_id": location_id})
        return result > 0
    except Exception as e:
        logger.error(f"Error deleting server location: {e}")
        return False

async def update_server_location_status(location_id: int, status: str, current_load: float = None) -> bool:
    """Update server location status and load"""
    try:
        query = """
        UPDATE server_locations 
        SET status = :status, 
            current_load = COALESCE(:current_load, current_load),
            last_updated = CURRENT_TIMESTAMP
        WHERE id = :id
        """
        values = {
            "id": location_id,
            "status": status,
            "current_load": current_load
        }
        await database.execute(query, values)
        return True
    except Exception as e:
        logger.error(f"Error updating server location status: {e}")
        return False

async def get_server_location_stats() -> Dict:
    """Get server location statistics"""
    query = """
    SELECT 
        status,
        COUNT(*) as count,
        AVG(current_load) as avg_load,
        SUM(active_users) as total_users
    FROM server_locations 
    GROUP BY status
    """
    results = await database.fetch_all(query)
    
    stats = {
        "by_status": results,
        "total_locations": sum(row['count'] for row in results),
        "total_active_users": sum(row['total_users'] for row in results)
    }
    
    return stats

# ==================== SYSTEM MAINTENANCE OPERATIONS ====================

async def cleanup_old_data(retention_days: int = 90) -> Dict[str, int]:
    """Clean up old data across all tables"""
    cleanup_stats = {}
    
    try:
        # Clean up old agent data
        cleanup_stats['agent_data'] = await cleanup_old_agent_data(retention_days)
        
        # Clean up old visitor logs
        cleanup_stats['visitor_logs'] = await cleanup_old_visitor_logs(retention_days)
        
        # Clean up old user activity logs (keep longer for audit)
        activity_retention = max(retention_days, 365)  # Keep at least 1 year of user activity
        query = """
        DELETE FROM user_activity 
        WHERE created_at < (NOW() - (:days * INTERVAL '1 day'))
        """
        cleanup_stats['user_activity'] = await database.execute(query, {"days": activity_retention})
        
        # Clean up old notifications (keep 30 days)
        query = """
        DELETE FROM notifications 
        WHERE created_at < (NOW() - INTERVAL '30 days')
        AND (read = true OR priority = 'low')
        """
        cleanup_stats['notifications'] = await database.execute(query)
        
        # Clean up resolved incidents older than 1 year
        query = """
        DELETE FROM incidents 
        WHERE status IN ('resolved', 'closed')
        AND resolved_at < (NOW() - INTERVAL '365 days')
        """
        cleanup_stats['incidents'] = await database.execute(query)
        
        logger.info(f"Data cleanup completed: {cleanup_stats}")
        return cleanup_stats
        
    except Exception as e:
        logger.error(f"Error during data cleanup: {e}")
        return cleanup_stats

async def get_system_stats() -> Dict[str, Any]:
    """Get comprehensive system statistics"""
    stats = {}
    
    try:
        # Basic counts
        stats['total_users'] = await database.fetch_val("SELECT COUNT(*) FROM users WHERE disabled = false")
        stats['total_servers'] = await database.fetch_val("SELECT COUNT(*) FROM servers")
        stats['total_incidents'] = await database.fetch_val("SELECT COUNT(*) FROM incidents")
        stats['open_incidents'] = await database.fetch_val("SELECT COUNT(*) FROM incidents WHERE status = 'open'")
        
        # Recent activity
        stats['recent_agent_data'] = await database.fetch_val("""
            SELECT COUNT(*) FROM agent_data 
            WHERE created_at >= (NOW() - INTERVAL '1 hour')
        """)
        
        stats['recent_incidents'] = await database.fetch_val("""
            SELECT COUNT(*) FROM incidents 
            WHERE created_at >= (NOW() - INTERVAL '24 hours')
        """)
        
        # Alert rules
        stats['active_alert_rules'] = await database.fetch_val("SELECT COUNT(*) FROM alert_rules WHERE active = true")
        
        # AI insights
        stats['recent_ai_insights'] = await database.fetch_val("""
            SELECT COUNT(*) FROM ai_insights 
            WHERE created_at >= (NOW() - INTERVAL '24 hours')
            AND confidence >= 0.7
        """)
        
        # Storage usage (approximate)
        stats['approximate_storage_mb'] = await database.fetch_val("""
            SELECT SUM(LENGTH(data)) / (1024 * 1024) as storage_mb 
            FROM agent_data 
            WHERE created_at >= (NOW() - INTERVAL '7 days')
        """) or 0
        
        return stats
        
    except Exception as e:
        logger.error(f"Error getting system stats: {e}")
        return stats

# ==================== HEALTH CHECK OPERATIONS ====================

async def health_check() -> Dict[str, Any]:
    """Perform comprehensive health check of the system"""
    health = {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "components": {}
    }
    
    try:
        # Database connectivity
        try:
            db_result = await database.fetch_one("SELECT 1 as check_value")
            health["components"]["database"] = {
                "status": "healthy" if db_result and db_result["check_value"] == 1 else "unhealthy",
                "details": "Database connection successful"
            }
        except Exception as e:
            health["components"]["database"] = {
                "status": "unhealthy",
                "details": f"Database connection failed: {str(e)}"
            }
            health["status"] = "unhealthy"
        
        # Check critical tables
        critical_tables = ["users", "servers", "agent_data", "alert_rules"]
        for table in critical_tables:
            try:
                count = await database.fetch_val(f"SELECT COUNT(*) FROM {table} LIMIT 1")
                health["components"][f"table_{table}"] = {
                    "status": "healthy",
                    "details": f"Table accessible with {count} records"
                }
            except Exception as e:
                health["components"][f"table_{table}"] = {
                    "status": "unhealthy",
                    "details": f"Table check failed: {str(e)}"
                }
                health["status"] = "unhealthy"
        
        # Check recent data flow
        recent_data = await database.fetch_val("""
            SELECT COUNT(*) FROM agent_data 
            WHERE created_at >= (NOW() - INTERVAL '5 minutes')
        """)
        health["components"]["data_flow"] = {
            "status": "healthy" if recent_data > 0 else "warning",
            "details": f"{recent_data} data points in last 5 minutes"
        }
        
        # Check alert processing
        recent_alerts = await database.fetch_val("""
            SELECT COUNT(*) FROM incidents 
            WHERE created_at >= (NOW() - INTERVAL '10 minutes')
        """)
        health["components"]["alert_processing"] = {
            "status": "healthy",
            "details": f"{recent_alerts} incidents created in last 10 minutes"
        }
        
        return health
        
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return {
            "status": "unhealthy",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "error": str(e),
            "components": {}
        }

# Export commonly used functions
__all__ = [
    # User operations
    'create_user', 'get_user_by_username', 'get_user_by_email', 'get_user_by_id',
    'get_all_users', 'update_user_last_login', 'update_user_role', 'disable_user',
    'enable_user', 'update_user_password', 'delete_user', 'verify_user_credentials',
    
    # User preferences
    'create_user_preference', 'get_user_preference', 'get_all_user_preferences',
    'update_user_preference', 'delete_user_preference',
    
    # Server operations
    'create_server', 'get_all_servers', 'get_server_by_id', 'get_server_by_hostname',
    'update_server_last_seen', 'update_server', 'delete_server',
    
    # Agent data operations
    'create_agent_data', 'get_latest_agent_data', 'get_all_agent_data',
    'get_agent_data_by_id', 'get_agent_data_stats', 'cleanup_old_agent_data',
    
    # Historical metrics
    'get_historical_metrics', 'get_metric_statistics', 'get_metrics_trend',
    
    # Alert and incident operations
    'check_agent_data_for_alerts', 'create_incident', 'get_incidents',
    'get_incident', 'update_incident_status', 'get_incident_stats',
    
    # AI insights
    'create_ai_insight', 'get_ai_insights', 'get_recent_ai_insights',
    'generate_ai_insights',
    
    # AI Feedback
    'store_ai_feedback', 'get_ai_feedback', 'get_ai_feedback_stats',
    
    # User activity and visitor logs
    'log_user_activity', 'get_user_activities', 'log_visitor_request_fixed',
    'get_visitor_logs', 'get_visitor_stats',
    
    # Alert rules
    'create_alert_rule', 'get_alert_rules', 'get_alert_rule', 'update_alert_rule',
    'delete_alert_rule', 'toggle_alert_rule',
    
    # Dashboard layouts
    'create_dashboard_layout', 'get_user_dashboard_layouts', 'get_dashboard_layout',
    'update_dashboard_layout', 'delete_dashboard_layout', 'set_default_layout',
    'get_default_layout',
    
    # Notifications
    'create_notification', 'get_notifications', 'mark_notification_read',
    'mark_all_notifications_read', 'get_unread_notifications_count',
    
    # Server locations
    'create_server_location', 'get_server_locations', 'get_server_location_by_id',
    'update_server_location', 'delete_server_location', 'update_server_location_status',
    'get_server_location_stats',
    
    # System operations
    'cleanup_old_data', 'get_system_stats', 'health_check'
]
