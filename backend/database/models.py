from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Boolean
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from datetime import datetime

from backend.database.database import Base


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)

    scan_type = Column(String, nullable=False)
    status = Column(String, default="completed")

    total_findings = Column(Integer, default=0)
    high_findings = Column(Integer, default=0)
    medium_findings = Column(Integer, default=0)
    low_findings = Column(Integer, default=0)

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now()
    )

    findings = relationship("Finding", back_populates="scan")


class Resource(Base):
    __tablename__ = "resources"

    id = Column(Integer, primary_key=True, index=True)

    resource_id = Column(String, nullable=False, unique=True)
    resource_type = Column(String, nullable=False)

    resource_name = Column(String, nullable=True)
    region = Column(String, nullable=True)

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now()
    )

    findings = relationship("Finding", back_populates="resource")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)

    title = Column(String, nullable=False)
    description = Column(String, nullable=True)

    severity = Column(String, nullable=False)
    status = Column(String, default="open")

    recommendation = Column(String, nullable=True)

    scan_id = Column(
        Integer,
        ForeignKey("scans.id"),
        nullable=True
    )

    resource_id = Column(
        Integer,
        ForeignKey("resources.id"),
        nullable=True
    )

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now()
    )

    scan = relationship("Scan", back_populates="findings")
    resource = relationship("Resource", back_populates="findings")

class RiskScore(Base):
    __tablename__ = "risk_scores"

    id = Column(Integer, primary_key=True, index=True)

    finding_id = Column(
        Integer,
        ForeignKey("findings.id"),
        nullable=False
    )

    score = Column(Integer, nullable=False)

    risk_level = Column(String, nullable=False)

    calculated_at = Column(
        DateTime(timezone=True),
        server_default=func.now()
    )

    finding = relationship("Finding")

class RemediationLog(Base):
    __tablename__ = "remediation_logs"

    id = Column(Integer, primary_key=True, index=True)

    finding_id = Column(
        Integer,
        ForeignKey("findings.id"),
        nullable=False
    )

    action = Column(String, nullable=False)

    approval_status = Column(
        String,
        default="pending"
    )

    execution_status = Column(
        String,
        default="not_executed"
    )

    rollback_status = Column(
        String,
        default="not_required"
    )

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now()
    )

    finding = relationship("Finding")

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)

    action = Column(String, nullable=False)
    resource_type = Column(String, nullable=True)
    resource_id = Column(String, nullable=True)

    details = Column(String, nullable=True)

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now()
    )

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)

    username = Column(String, nullable=False, unique=True)
    email = Column(String, nullable=False, unique=True)

    role = Column(String, default="user")

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now()
    )

class Remediation(Base):
    __tablename__ = "remediations"

    id = Column(Integer, primary_key=True, index=True)

    finding_id = Column(Integer, nullable=True)

    title = Column(String, nullable=False)

    description = Column(String, nullable=True)

    recommendation = Column(String, nullable=True)

    status = Column(
        String,
        default="PENDING"
    )

    approved = Column(
        Boolean,
        default=False
    )

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now()
    )