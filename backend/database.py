import os
from sqlmodel import create_engine, Session, SQLModel
from typing import Generator

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    # Fallback for local development if .env is not sourced
    # This should ideally be handled by proper environment management
    DATABASE_URL = "postgresql://user:password@localhost:5432/todoapp"


# For Neon Serverless PostgreSQL, we need to configure the engine with proper connection pooling
# and SSL settings
engine = create_engine(
    DATABASE_URL,
    connect_args={
        "sslmode": "require",  # Required for Neon
        "connect_timeout": 10,  # Set a reasonable timeout
    },
    pool_pre_ping=True,  # Helps with stale connections in serverless environments
    pool_recycle=300,  # Recycle connections to prevent issues with serverless
    echo=False  # Set to True for SQL query logging during debugging
)

def create_db_and_tables():
    SQLModel.metadata.create_all(engine)

def get_session() -> Generator[Session, None, None]:
    with Session(engine) as session:
        yield session
