from pydantic import BaseModel
from datetime import datetime
from typing import Optional, Dict, Any

# Alerting Models
class AlertRuleBase(BaseModel):
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
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

class IncidentBase(BaseModel):
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
    status: str = "new"
    created_at: datetime
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
    status: str
    count: int
