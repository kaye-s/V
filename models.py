import os
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, ForeignKey, Numeric, Enum
from sqlalchemy.orm import declarative_base, relationship, sessionmaker
from datetime import datetime
import enum
from dotenv import load_dotenv

load_dotenv()

Base = declarative_base()

# Severity Enum
class SeverityEnum(enum.Enum):
    Low = "Low"
    Medium = "Medium"
    High = "High"
    Critical = "Critical"


class User(Base):
    __tablename__ = "users"

    user_id = Column(Integer, primary_key=True, autoincrement=True)
    email = Column(String(255), unique=True, nullable=False)
    password_hash = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    submissions = relationship("CodeSubmission", back_populates="user")


class CodeSubmission(Base):
    __tablename__ = "code_submissions"

    submission_id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.user_id", ondelete="CASCADE"), nullable=False)
    submission_name = Column(String(255))
    uploaded_at = Column(DateTime, default=datetime.utcnow)
    overall_risk_score = Column(Numeric(5,2))
    simplified_summary = Column(Text)
    detailed_summary = Column(Text)

    user = relationship("User", back_populates="submissions")
    files = relationship("File", back_populates="submission")
    threats = relationship("Threat", back_populates="submission")


class File(Base):
    __tablename__ = "files"

    file_id = Column(Integer, primary_key=True, autoincrement=True)
    submission_id = Column(Integer, ForeignKey("code_submissions.submission_id", ondelete="CASCADE"), nullable=False)
    file_name = Column(String(255), nullable=False)
    file_path = Column(Text, nullable=False)
    file_type = Column(String(100))

    submission = relationship("CodeSubmission", back_populates="files")
    threats = relationship("Threat", back_populates="file")


class Threat(Base):
    __tablename__ = "threats"

    threat_id = Column(Integer, primary_key=True, autoincrement=True)
    submission_id = Column(Integer, ForeignKey("code_submissions.submission_id", ondelete="CASCADE"), nullable=False)
    file_id = Column(Integer, ForeignKey("files.file_id", ondelete="SET NULL"), nullable=True)
    title = Column(String(255), nullable=False)
    description = Column(Text)
    severity_level = Column(Enum(SeverityEnum), nullable=False)
    severity_score = Column(Numeric(5,2))
    recommendation = Column(Text)
    line_number = Column(Integer)

    submission = relationship("CodeSubmission", back_populates="threats")
    file = relationship("File", back_populates="threats")
