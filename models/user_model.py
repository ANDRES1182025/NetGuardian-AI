from sqlalchemy import Column, Integer, String
from sqlalchemy.orm import relationship
from database.connection import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    password = Column(String, nullable=False)
    role = Column(String, default="analyst", nullable=False)  # 'admin', 'analyst', 'guest'

    # Relación con la tabla de escaneos
    scans = relationship("Scan", back_populates="user", cascade="all, delete-orphan")

# Alias para mantener la compatibilidad con imports anteriores
UserModel = User