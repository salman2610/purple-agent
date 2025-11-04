from database import database
from passlib.context import CryptContext
from datetime import datetime
from typing import List, Optional, Dict, Any
import json

# Password hashing
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")

# User CRUD operations
async def create_user(username: str, email: str, password: str, role: str = "guest"):
    hashed_password = pwd_context.hash(password)
    query = """
    INSERT INTO users (username, email, hashed_password, role)
    VALUES (:username, :email, :hashed_password, :role)
    RETURNING id
    """
    values = {
        "username": username,
        "email": email,
        "hashed_password": hashed_password,
        "role": role
    }
    result = await database.fetch_one(query, values)
    return result["id"] if result else None

async def get_user_by_username(username: str):
    query = "SELECT * FROM users WHERE username = :username"
    return await database.fetch_one(query, {"username": username})

async def get_user_by_email(email: str):
    query = "SELECT * FROM users WHERE email = :email"
    return await database.fetch_one(query, {"email": email})

async def get_user_by_id(user_id: int):
    query = "SELECT * FROM users WHERE id = :id"
    return await database.fetch_one(query, {"id": user_id})

async def get_all_users():
    query = "SELECT * FROM users ORDER BY created_at DESC"
    return await database.fetch_all(query)

async def update_user_last_login(user_id: int):
    query = "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = :id"
    await database.execute(query, {"id": user_id})

async def update_user_role(user_id: int, role: str):
    query = "UPDATE users SET role = :role WHERE id = :id"
    await database.execute(query, {"id": user_id, "role": role})

async def disable_user(user_id: int):
    query = "UPDATE users SET disabled = true WHERE id = :id"
    await database.execute(query, {"id": user_id})

async def enable_user(user_id: int):
    query = "UPDATE users SET disabled = false WHERE id = :id"
    await database.execute(query, {"id": user_id})

async def update_user_password(user_id: int, new_password: str):
    hashed_password = pwd_context.hash(new_password)
    query = "UPDATE users SET hashed_password = :hashed_password WHERE id = :id"
    await database.execute(query, {"id": user_id, "hashed_password": hashed_password})

# Agent Data CRUD operations
async def create_agent_data(data: dict):
    """
    Store agent data in the database
    """
    try:
        # Convert the entire data dict to JSON string for storage
        data_json = json.dumps(data)
        
        # Handle timestamp conversion
        timestamp_str = data.get('timestamp')
        timestamp_obj = None
        
        if timestamp_str:
            try:
                # Parse ISO format string to datetime object
                if timestamp_str.endswith('Z'):
                    timestamp_str = timestamp_str[:-1]  # Remove 'Z' for parsing
                timestamp_obj = datetime.fromisoformat(timestamp_str)
            except (ValueError, TypeError):
                # If parsing fails, use current time
                timestamp_obj = datetime.utcnow()
        else:
            timestamp_obj = datetime.utcnow()
        
        query = """
        INSERT INTO agent_data (data, timestamp)
        VALUES (:data, :timestamp)
        RETURNING id
        """
        values = {
            "data": data_json,
            "timestamp": timestamp_obj
        }
        
        result = await database.fetch_one(query, values)
        return result["id"] if result else None
        
    except Exception as e:
        print(f"Error creating agent data: {e}")
        return None

async def get_latest_agent_data():
    query = """
    SELECT * FROM agent_data 
    ORDER BY created_at DESC 
    LIMIT 1
    """
    result = await database.fetch_one(query)
    if result:
        # Parse the JSON data back to dict
        result_dict = dict(result)
        if 'data' in result_dict and isinstance(result_dict['data'], str):
            try:
                result_dict['data'] = json.loads(result_dict['data'])
            except json.JSONDecodeError:
                pass
        return result_dict
    return None

async def get_all_agent_data():
    query = "SELECT * FROM agent_data ORDER BY created_at DESC"
    results = await database.fetch_all(query)
    
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

async def get_agent_data_by_id(data_id: int):
    query = "SELECT * FROM agent_data WHERE id = :id"
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

# Alert Rules CRUD - FIXED VERSION for SQLite
async def create_alert_rule(alert_rule: dict, user_id: int):
    query = """
    INSERT INTO alert_rules (metric, threshold_value, comparison_operator, severity, active, description, created_by, created_at, updated_at)
    VALUES (:metric, :threshold_value, :comparison_operator, :severity, :active, :description, :created_by, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
    RETURNING *
    """
    values = {**alert_rule, "created_by": user_id}
    result = await database.fetch_one(query, values)
    
    # Ensure datetime fields are properly handled
    if result:
        result_dict = dict(result)
        # Convert None to current time if needed
        if not result_dict.get('created_at'):
            result_dict['created_at'] = datetime.utcnow()
        if not result_dict.get('updated_at'):
            result_dict['updated_at'] = datetime.utcnow()
        return result_dict
    return None

async def get_alert_rules(active_only: bool = True):
    query = "SELECT * FROM alert_rules"
    if active_only:
        query += " WHERE active = true"
    query += " ORDER BY created_at DESC"
    results = await database.fetch_all(query)
    
    # Ensure datetime fields are properly handled
    processed_results = []
    for result in results:
        result_dict = dict(result)
        if not result_dict.get('created_at'):
            result_dict['created_at'] = datetime.utcnow()
        if not result_dict.get('updated_at'):
            result_dict['updated_at'] = datetime.utcnow()
        processed_results.append(result_dict)
    
    return processed_results

async def get_alert_rule(rule_id: int):
    query = "SELECT * FROM alert_rules WHERE id = :id"
    result = await database.fetch_one(query, {"id": rule_id})
    if result:
        result_dict = dict(result)
        # Ensure datetime fields are properly handled
        if not result_dict.get('created_at'):
            result_dict['created_at'] = datetime.utcnow()
        if not result_dict.get('updated_at'):
            result_dict['updated_at'] = datetime.utcnow()
        return result_dict
    return None

async def update_alert_rule(rule_id: int, alert_rule: dict):
    query = """
    UPDATE alert_rules 
    SET metric = :metric, threshold_value = :threshold_value, comparison_operator = :comparison_operator,
        severity = :severity, active = :active, description = :description, updated_at = CURRENT_TIMESTAMP
    WHERE id = :id
    RETURNING *
    """
    values = {**alert_rule, "id": rule_id}
    result = await database.fetch_one(query, values)
    if result:
        result_dict = dict(result)
        # Ensure datetime fields are properly handled
        if not result_dict.get('updated_at'):
            result_dict['updated_at'] = datetime.utcnow()
        return result_dict
    return None

async def delete_alert_rule(rule_id: int):
    query = "DELETE FROM alert_rules WHERE id = :id"
    return await database.execute(query, {"id": rule_id})

async def toggle_alert_rule(rule_id: int, active: bool):
    query = "UPDATE alert_rules SET active = :active, updated_at = CURRENT_TIMESTAMP WHERE id = :id RETURNING *"
    result = await database.fetch_one(query, {"active": active, "id": rule_id})
    if result:
        result_dict = dict(result)
        # Ensure datetime fields are properly handled
        if not result_dict.get('updated_at'):
            result_dict['updated_at'] = datetime.utcnow()
        return result_dict
    return None

# Incidents CRUD - FIXED VERSION for SQLite
async def create_incident(incident: dict):
    query = """
    INSERT INTO incidents (alert_rule_id, agent_data_id, incident_type, message, severity, metadata, created_at)
    VALUES (:alert_rule_id, :agent_data_id, :incident_type, :message, :severity, :metadata, CURRENT_TIMESTAMP)
    RETURNING *
    """
    
    # Ensure metadata is properly formatted as JSON string
    if 'metadata' in incident and incident['metadata'] is not None:
        if isinstance(incident['metadata'], dict):
            incident['metadata'] = json.dumps(incident['metadata'])
    
    result = await database.fetch_one(query, incident)
    if result:
        result_dict = dict(result)
        # Ensure datetime fields are properly handled
        if not result_dict.get('created_at'):
            result_dict['created_at'] = datetime.utcnow()
        return result_dict
    return None

async def get_incidents(status: str = None, severity: str = None, limit: int = 100, offset: int = 0):
    query = "SELECT * FROM incidents WHERE 1=1"
    values = {"limit": limit, "offset": offset}
    
    if status:
        query += " AND status = :status"
        values["status"] = status
    
    if severity:
        query += " AND severity = :severity"
        values["severity"] = severity
        
    query += " ORDER BY created_at DESC LIMIT :limit OFFSET :offset"
    
    results = await database.fetch_all(query, values)
    
    # Parse metadata JSON back to dict and ensure datetime fields
    parsed_results = []
    for result in results:
        result_dict = dict(result)
        if 'metadata' in result_dict and result_dict['metadata'] and isinstance(result_dict['metadata'], str):
            try:
                result_dict['metadata'] = json.loads(result_dict['metadata'])
            except json.JSONDecodeError:
                result_dict['metadata'] = {}
        
        # Ensure datetime fields are properly handled
        if not result_dict.get('created_at'):
            result_dict['created_at'] = datetime.utcnow()
        
        parsed_results.append(result_dict)
    
    return parsed_results

async def get_incident(incident_id: int):
    query = "SELECT * FROM incidents WHERE id = :id"
    result = await database.fetch_one(query, {"id": incident_id})
    if result:
        result_dict = dict(result)
        if 'metadata' in result_dict and result_dict['metadata'] and isinstance(result_dict['metadata'], str):
            try:
                result_dict['metadata'] = json.loads(result_dict['metadata'])
            except json.JSONDecodeError:
                result_dict['metadata'] = {}
        
        # Ensure datetime fields are properly handled
        if not result_dict.get('created_at'):
            result_dict['created_at'] = datetime.utcnow()
        
        return result_dict
    return None

async def update_incident_status(incident_id: int, status: str, user_id: int = None, notes: str = None):
    query = """
    UPDATE incidents 
    SET status = :status, 
        acknowledged_by = CASE WHEN :status = 'acknowledged' AND acknowledged_by IS NULL THEN :user_id ELSE acknowledged_by END,
        acknowledged_at = CASE WHEN :status = 'acknowledged' AND acknowledged_at IS NULL THEN CURRENT_TIMESTAMP ELSE acknowledged_at END,
        resolved_by = CASE WHEN :status IN ('resolved', 'closed') THEN :user_id ELSE resolved_by END,
        resolved_at = CASE WHEN :status IN ('resolved', 'closed') THEN CURRENT_TIMESTAMP ELSE resolved_at END,
        resolved_notes = COALESCE(:notes, resolved_notes)
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
        
        # Ensure datetime fields are properly handled
        if not result_dict.get('created_at'):
            result_dict['created_at'] = datetime.utcnow()
        
        return result_dict
    return None

async def get_incident_stats():
    query = """
    SELECT 
        status,
        COUNT(*) as count
    FROM incidents 
    GROUP BY status
    ORDER BY status
    """
    return await database.fetch_all(query)

async def get_incidents_count(status: str = None):
    query = "SELECT COUNT(*) as count FROM incidents"
    values = {}
    if status:
        query += " WHERE status = :status"
        values["status"] = status
    result = await database.fetch_one(query, values)
    return result["count"] if result else 0

async def get_recent_incidents(hours: int = 24):
    query = """
    SELECT * FROM incidents 
    WHERE created_at >= datetime('now', '-' || :hours || ' hours')
    ORDER BY created_at DESC
    """
    results = await database.fetch_all(query, {"hours": hours})
    
    # Parse metadata JSON back to dict and ensure datetime fields
    parsed_results = []
    for result in results:
        result_dict = dict(result)
        if 'metadata' in result_dict and result_dict['metadata'] and isinstance(result_dict['metadata'], str):
            try:
                result_dict['metadata'] = json.loads(result_dict['metadata'])
            except json.JSONDecodeError:
                result_dict['metadata'] = {}
        
        # Ensure datetime fields are properly handled
        if not result_dict.get('created_at'):
            result_dict['created_at'] = datetime.utcnow()
        
        parsed_results.append(result_dict)
    
    return parsed_results

# Dashboard Layouts CRUD operations
async def create_dashboard_layout(user_id: int, name: str, layout: dict, widgets: dict, filters: dict = None):
    query = """
    INSERT INTO user_dashboard_layouts (user_id, name, layout, widgets, filters, created_at, updated_at)
    VALUES (:user_id, :name, :layout, :widgets, :filters, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
    RETURNING *
    """
    values = {
        "user_id": user_id,
        "name": name,
        "layout": json.dumps(layout),
        "widgets": json.dumps(widgets),
        "filters": json.dumps(filters) if filters else None
    }
    result = await database.fetch_one(query, values)
    return dict(result) if result else None

async def get_user_dashboard_layouts(user_id: int):
    query = "SELECT * FROM user_dashboard_layouts WHERE user_id = :user_id ORDER BY updated_at DESC"
    results = await database.fetch_all(query, {"user_id": user_id})
    
    layouts = []
    for result in results:
        layout_dict = dict(result)
        # Parse JSON fields
        for field in ['layout', 'widgets', 'filters']:
            if layout_dict.get(field) and isinstance(layout_dict[field], str):
                try:
                    layout_dict[field] = json.loads(layout_dict[field])
                except json.JSONDecodeError:
                    layout_dict[field] = {}
        layouts.append(layout_dict)
    
    return layouts

async def get_dashboard_layout(layout_id: int, user_id: int):
    query = "SELECT * FROM user_dashboard_layouts WHERE id = :id AND user_id = :user_id"
    result = await database.fetch_one(query, {"id": layout_id, "user_id": user_id})
    
    if result:
        layout_dict = dict(result)
        # Parse JSON fields
        for field in ['layout', 'widgets', 'filters']:
            if layout_dict.get(field) and isinstance(layout_dict[field], str):
                try:
                    layout_dict[field] = json.loads(layout_dict[field])
                except json.JSONDecodeError:
                    layout_dict[field] = {}
        return layout_dict
    
    return None

async def update_dashboard_layout(layout_id: int, user_id: int, name: str = None, layout: dict = None, widgets: dict = None, filters: dict = None):
    query = """
    UPDATE user_dashboard_layouts 
    SET updated_at = CURRENT_TIMESTAMP
    """
    values = {"id": layout_id, "user_id": user_id}
    
    if name is not None:
        query += ", name = :name"
        values["name"] = name
        
    if layout is not None:
        query += ", layout = :layout"
        values["layout"] = json.dumps(layout)
        
    if widgets is not None:
        query += ", widgets = :widgets"
        values["widgets"] = json.dumps(widgets)
        
    if filters is not None:
        query += ", filters = :filters"
        values["filters"] = json.dumps(filters)
        
    query += " WHERE id = :id AND user_id = :user_id RETURNING *"
    
    result = await database.fetch_one(query, values)
    return dict(result) if result else None

async def delete_dashboard_layout(layout_id: int, user_id: int):
    query = "DELETE FROM user_dashboard_layouts WHERE id = :id AND user_id = :user_id"
    await database.execute(query, {"id": layout_id, "user_id": user_id})
    return True

async def set_default_layout(layout_id: int, user_id: int):
    """Set a layout as default for user"""
    try:
        # First, unset any existing default for this user
        await database.execute(
            "UPDATE user_dashboard_layouts SET is_default = FALSE WHERE user_id = :user_id",
            {"user_id": user_id}
        )
        
        # Then set the new default
        await database.execute(
            "UPDATE user_dashboard_layouts SET is_default = TRUE WHERE id = :layout_id AND user_id = :user_id",
            {"layout_id": layout_id, "user_id": user_id}
        )
        return True
    except Exception as e:
        print(f"Error setting default layout: {e}")
        return False

async def get_default_layout(user_id: int):
    """Get user's default dashboard layout"""
    query = "SELECT * FROM user_dashboard_layouts WHERE user_id = :user_id AND is_default = TRUE"
    return await database.fetch_one(query, {"user_id": user_id})
