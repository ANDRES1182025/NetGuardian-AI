from sqlalchemy import Column, Integer, String, ForeignKey, DateTime, JSON
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from database.connection import Base

class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    target = Column(String, nullable=False)
    vulnerability_found = Column(String, nullable=True)
    severity = Column(String, nullable=False, default="Bajo")
    inspection_type = Column(String, nullable=True, default="Análisis Rápido de Red")
    
    # Campo de Telemetría Activa (Puertos TCP y Directorios/Endpoints)
    active_telemetry = Column(JSON, nullable=True)
    
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    
    # Campo de fecha y hora
    scanned_at = Column(DateTime(timezone=True), server_default=func.now())

    # Relación
    user = relationship("User", back_populates="scans", lazy="joined")