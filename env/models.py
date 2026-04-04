from pydantic import BaseModel
from typing import List, Optional

class Alert(BaseModel):
    id: str
    type: str
    severity: str
    description: str
    source_ip: str

class LogEntry(BaseModel):
    timestamp: str
    ip: str
    event: str

class Observation(BaseModel):
    alerts: List[Alert]
    logs: List[LogEntry]
    current_alert: Optional[Alert]
    history: List[str]

class Action(BaseModel):
    action_type: str
    target_id: Optional[str] = None
    query: Optional[str] = None
    content: Optional[str] = None

class Reward(BaseModel):
    score: float
    reason: str
