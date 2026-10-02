"""
CYBERTRACE - Pydantic Data Models & Schemas
Clean type specifications for normalized events, IOCs, and correlated incidents.
"""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any

class NormalizedEvent(BaseModel):
    timestamp: Optional[str] = None
    source_ip: Optional[str] = None
    username: Optional[str] = None
    event_type: str = "OTHER"
    message: str
    severity: str = "LOW"
    raw_log: Optional[str] = None
    extra_data: Dict[str, Any] = Field(default_factory=dict)

class IOCItem(BaseModel):
    ioc_type: str  # "IPv4", "DOMAIN", "URL", "USERNAME", "FILE_PATH"
    ioc_value: str
    is_suspicious: bool = False
    context: Optional[str] = None
    first_seen: Optional[str] = None

class IncidentItem(BaseModel):
    id: Optional[int] = None
    incident_code: str
    title: str
    incident_type: str
    risk_score: int
    risk_level: str  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    source_ip: Optional[str] = None
    username: Optional[str] = None
    first_observed: Optional[str] = None
    last_observed: Optional[str] = None
    event_count: int = 0
    attack_pattern: str
    contributing_factors: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    rules_triggered: List[str] = Field(default_factory=list)
    event_indices: List[int] = Field(default_factory=list)
    timeline: Optional[List[Dict[str, Any]]] = None

class AnalysisRunSummary(BaseModel):
    id: int
    run_uuid: str
    filename: str
    file_size: int
    uploaded_at: str
    total_events: int
    suspicious_events: int
    total_incidents: int
    critical_incidents: int
    max_risk_score: int
    summary_json: Optional[str] = None

class StatisticsResponse(BaseModel):
    total_events: int
    suspicious_events: int
    total_incidents: int
    critical_incidents: int
    unique_ips: int
    total_iocs: int

class UploadAnalysisResponse(BaseModel):
    success: bool
    message: str
    run_id: int
    run_uuid: str
    filename: str
    total_events: int
    suspicious_events: int
    total_incidents: int
    max_risk_score: int
