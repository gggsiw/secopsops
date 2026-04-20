from pydantic import BaseModel
from typing import List, Optional, Dict, Any


class Alert(BaseModel):
    id: str
    type: str
    severity: str
    description: str
    source_ip: str
    destination_ip: Optional[str] = None
    user: Optional[str] = None
    timestamp: Optional[str] = None
    tags: List[str] = []


class LogEntry(BaseModel):
    timestamp: str
    ip: str
    event: str
    user: Optional[str] = None
    details: Optional[str] = None


class Ticket(BaseModel):
    ticket_id: str
    alert_id: str
    status: str          # open | in_progress | escalated | closed
    priority: str        # P1 | P2 | P3
    assigned_to: str
    notes: str = ""


class SIEMResult(BaseModel):
    query: str
    matched_logs: List[LogEntry]
    risk_score: float
    summary: str


class Observation(BaseModel):
    alerts: List[Alert]
    logs: List[LogEntry]
    current_alert: Optional[Alert]
    history: List[str]
    tickets: List[Ticket] = []
    siem_results: List[SIEMResult] = []
    step_index: int = 0
    cumulative_reward: float = 0.0


class Action(BaseModel):
    action_type: str                    # investigate | query_logs | block_ip | escalate | close | report | create_ticket | query_siem
    target_id: Optional[str] = None     # alert id to target
    query: Optional[str] = None         # IP or search string
    content: Optional[str] = None       # notes / ticket content
    priority: Optional[str] = None      # P1 | P2 | P3 for tickets


class Reward(BaseModel):
    score: float
    reason: str
    speed_bonus: float = 0.0
    chain_bonus: float = 0.0
    false_positive_penalty: float = 0.0
    final_score: float = 0.0
