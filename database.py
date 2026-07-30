"""
Database configuration and models for the Task Manager API.

This module defines:
    - The SQLite database connection (engine)
    - The User model (stores accounts and hashed passwords)
    - The Task model (stores tasks, each linked to one user)
"""

from sqlalchemy import (
    Column,
    Integer,
    String,
    Boolean,
    ForeignKey,
    create_engine,
)
from sqlalchemy.orm import declarative_base, sessionmaker

# Connection to the SQLite database file.
# The file is created automatically on first run.
engine = create_engine("sqlite:///taskmanager.db")

# Base class that all models inherit from.
# SQLAlchemy uses it to map classes to database tables.
Base = declarative_base()


class User(Base):
    """A registered user of the API."""

    __tablename__ = "users"

    id = Column(Integer, primary_key=True)

    # unique=True prevents two accounts with the same username
    username = Column(String, unique=True)

    # Stores the bcrypt hash, never the raw password
    password = Column(String)

    def __str__(self):
        return f"user: {self.username}"


class Task(Base):
    """A single task that belongs to one user."""

    __tablename__ = "tasks"

    id = Column(Integer, primary_key=True)
    title = Column(String)

    # New tasks start as not completed
    done = Column(Boolean, default=False)

    # Links this task to a row in the users table
    user_id = Column(Integer, ForeignKey("users.id"))

    def __str__(self):
        status = "done" if self.done else "not complete"
        return f"{self.title} - {status}"


# Create all tables that do not exist yet
Base.metadata.create_all(engine)

# Factory used by main.py to open a database session
Session = sessionmaker(bind=engine)