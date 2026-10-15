import os
import logging
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, declarative_base

logger = logging.getLogger("cloudsentinel.database")

raw_database_url = os.getenv("DATABASE_URL", "").strip()

if not raw_database_url:
    DATABASE_URL = "sqlite:///./cloudsentinel.db"
    connect_args = {"check_same_thread": False}
    engine = create_engine(
        DATABASE_URL,
        connect_args=connect_args,
    )
else:
    # Explicitly configured DATABASE_URL (e.g. PostgreSQL)
    # SQLAlchemy requires postgresql:// or postgresql+psycopg2://
    # If legacy 'postgres://' is provided, normalize it to 'postgresql://'
    url = raw_database_url
    if url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql://", 1)

    DATABASE_URL = url

    if DATABASE_URL.startswith("sqlite"):
        connect_args = {"check_same_thread": False}
        engine = create_engine(DATABASE_URL, connect_args=connect_args)
    else:
        # PostgreSQL or other production DB
        engine = create_engine(
            DATABASE_URL,
            pool_pre_ping=True,      # Validate connection liveness on checkout
            pool_size=10,
            max_overflow=20,
            pool_recycle=1800,       # Recycle connections every 30 minutes
        )


def check_db_connection(engine_instance=None):
    """
    Validates connection to the database.
    If the explicitly configured database is unreachable, raises an error.
    """
    eng = engine_instance or engine
    with eng.connect() as conn:
        conn.execute(text("SELECT 1"))
    return True


SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()