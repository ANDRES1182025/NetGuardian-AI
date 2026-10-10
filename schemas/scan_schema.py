import re
from pydantic import BaseModel, Field, field_validator
from datetime import datetime
from typing import Dict, Any, List, Optional

TARGET_REGEX = re.compile(
    r'^(?:http[s]?://)?'
    r'(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}'
    r'|localhost'
    r'|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
    r'(?::\d+)?'
    r'(?:/?|[/?]\S+)?$', re.IGNORECASE
)


class PortResult(BaseModel):
    port: int
    state: str = "open"
    service: str


class PathResult(BaseModel):
    path: str
    status_code: int
    risk_level: str


class ActiveTelemetry(BaseModel):
    open_ports: List[PortResult] = []
    discovered_paths: List[PathResult] = []
    total_open_ports: int = 0
    total_paths_found: int = 0


class ScanRequest(BaseModel):
    target: str = Field(..., example="https://ejemplo.com")
    inspection_type: str = Field(default="quick", example="deep")
    severity: str = Field(default="Bajo", example="Alto")
    user_id: Optional[int] = 1

    @field_validator('target')
    @classmethod
    def sanitize_and_validate_target(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("El campo objetivo (target) no puede estar vacío.")

        forbidden_chars = [";", "&&", "||", "`", "$", "<", ">", "\n", "\r", "\t"]
        if any(char in value for char in forbidden_chars):
            raise ValueError("El objetivo contiene caracteres prohibidos o posibles intentos de inyección.")

        if not TARGET_REGEX.match(value):
            raise ValueError("Formato de objetivo inválido. Debe ser una URL (http/https), dominio o dirección IP válida.")

        return value

    @field_validator('inspection_type')
    @classmethod
    def validate_inspection_type(cls, value: str) -> str:
        value = value.strip()
        allowed_modes = ["quick", "deep", "Análisis Rápido de Red", "Inspección Profunda de Vulnerabilidades (IA)"]
        if value not in allowed_modes:
            raise ValueError(f"Modo de inspección no permitido. Opciones válidas: {', '.join(allowed_modes)}")
        return value

    @field_validator('severity')
    @classmethod
    def validate_severity(cls, value: str) -> str:
        value = value.strip().capitalize()
        allowed_severities = ["Bajo", "Medio", "Alto"]
        if value not in allowed_severities:
            raise ValueError("Severidad no válida. Debe ser 'Bajo', 'Medio' o 'Alto'.")
        return value


class ScanCreate(ScanRequest):
    pass


class ScanResponse(BaseModel):
    id: int
    target: str
    vulnerability_found: str
    severity: str
    inspection_type: Optional[str] = "Análisis Rápido de Red"
    active_telemetry: Optional[ActiveTelemetry] = None
    scanned_at: datetime
    user_id: Optional[int] = None

    class Config:
        from_attributes = True


class AIScanExecutionResult(BaseModel):
    scan_data: ScanResponse
    ai_details: Dict[str, Any]


class DashboardStats(BaseModel):
    total_scans: int
    severity_distribution: Dict[str, int]