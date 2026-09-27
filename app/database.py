import os
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, sessionmaker

DB_URL = os.getenv("SIEM_DB_URL", "sqlite:///./stage2cs_siem.db")
connect_args = {"check_same_thread": False} if DB_URL.startswith("sqlite") else {}
engine = create_engine(DB_URL, connect_args=connect_args, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)


class Base(DeclarativeBase):
    pass


def upgrade_legacy_sqlite_schema() -> None:
    """Keep databases created by version 1 usable without deleting analyst data."""
    if engine.dialect.name != "sqlite" or "alerts" not in inspect(engine).get_table_names():
        return
    existing = {column["name"] for column in inspect(engine).get_columns("alerts")}
    columns = {
        "updated_at": "DATETIME DEFAULT CURRENT_TIMESTAMP",
        "first_seen": "DATETIME DEFAULT CURRENT_TIMESTAMP",
        "last_seen": "DATETIME DEFAULT CURRENT_TIMESTAMP",
        "occurrence_count": "INTEGER NOT NULL DEFAULT 1",
        "case_id": "INTEGER",
        "suppression_key": "VARCHAR(512) NOT NULL DEFAULT ''",
        "assignee": "VARCHAR(255)",
        "resolution_reason": "TEXT NOT NULL DEFAULT ''",
    }
    with engine.begin() as connection:
        for name, definition in columns.items():
            if name not in existing:
                connection.execute(text(f"ALTER TABLE alerts ADD COLUMN {name} {definition}"))
        connection.execute(text("CREATE INDEX IF NOT EXISTS ix_alerts_last_seen ON alerts (last_seen)"))
        connection.execute(text("CREATE INDEX IF NOT EXISTS ix_alerts_case_id ON alerts (case_id)"))
        connection.execute(text("CREATE INDEX IF NOT EXISTS ix_alerts_suppression_key ON alerts (suppression_key)"))
        connection.execute(text("CREATE INDEX IF NOT EXISTS ix_alerts_assignee ON alerts (assignee)"))


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
