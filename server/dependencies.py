from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from models import SessionLocal

limiter= Limiter(key_func= get_remote_address)

def get_db():
    db= SessionLocal()
    try:
        yield db
    finally:
        db.close()