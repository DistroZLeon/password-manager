from fastapi import FastAPI, Depends, HTTPException, Request
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from pydantic import BaseModel
from sqlalchemy.orm import Session
from models import SessionLocal, User

limiter= Limiter(key_func= get_remote_address)
app= FastAPI(title= "Passphrases Vault API")
app.state.limiter= limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

def get_db():
    db= SessionLocal()
    try:
        yield db
    finally:
        db.close()

class RegisterRequest(BaseModel):
    username: str
    salt: str
    auth_tag: str
    vk_nonce: str
    encrypted_vk: str

class LoginRequest(BaseModel):
    username: str
    auth_tag: str

@app.post("/register")
@limiter.limit("20/minute")
def register_user(request: Request, req: RegisterRequest, db: Session= Depends(get_db)):
    if db.query(User).filter(User.username== req.username).first():
        raise HTTPException(status_code= 400, details= "Username already registered!")

    user= User(
        username= req.username,
        salt= req.salt,
        auth_tag= req.auth_tag,
        vk_nonce= req.vk_nonce,
        encrypted_vk= req.encrypted_vk
    )
    db.add(user)
    db.commit()
    return {"message": "User registered!"}

@app.post("/login")
@limiter.limit("5/minute")
def login_user(request: Request,req: LoginRequest, db: Session= Depends(get_db)):
    user= db.query(User).filter(User.username== req.username).first()

    if not user:
        raise HTTPException(status_code= 401, detail= "Invalid credentials")

    if user.locked:
        raise HTTPException(status_code= 401, detail= "Account locked")
    
    if user.auth_tag!= req.auth_tag:
        user.failed_attempts+= 1
        if user.failed_attempts>= 5:
            user.locked= True

        db.commit()
        raise HTTPException(status_code= 401, detail= "Invalid credentials")

    user.failed_attempts= 0
    db.commit()
        

    return{
        "salt": user.salt,
        "vk_nonce": user.vk_nonce,
        "encrypted_vk": user.encrypted_vk
    }