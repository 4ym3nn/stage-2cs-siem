import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import os
os.environ['SIEM_DB_URL']='sqlite:///./test_stage2cs_siem.db'
import pytest
from fastapi.testclient import TestClient
from app.database import Base, engine
from app.main import app

@pytest.fixture(autouse=True)
def reset_db():
    for name in ('SIEM_API_KEY', 'SIEM_INGEST_API_KEY', 'SIEM_ANALYST_API_KEY', 'SIEM_ADMIN_API_KEY'):
        os.environ.pop(name, None)
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)

@pytest.fixture
def client():
    return TestClient(app)
