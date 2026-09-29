from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from models import User
from schemas import RegisterRequest, LoginRequest
from dependencies import get_db, limiter

router= APIRouter(tags= ["Users"])

@router.get("/users/{username}/salt")
@limiter.limit("10/minute")
def get_salt(request: Request, username: str, db: Session= Depends(get_db)):
    user= db.query(User).filter(User.username== username).first()
    
    if not user:
        raise HTTPException(status_code= 404, detail= "User not found!")

    return {"salt": user.salt}

@router.post("/users/register")
@limiter.limit("20/minute")
def register_user(request: Request, req: RegisterRequest, db: Session= Depends(get_db)):
    if db.query(User).filter(User.username== req.username).first():
        raise HTTPException(status_code= 400, detail= "Username already registered!")

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

@router.post("/users/login")
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