from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from models import User, KeyPass
from schemas import KeyPassCreate, LoginRequest
from dependencies import get_db, limiter

router= APIRouter(tags= ["Keypasses"])

def authenticate_user(db: Session, username: str, auth_tag: str)-> User:
    """Verify identity"""

    user= db.query(User).filter(User.username== username).first()
    if not user or user.auth_tag!= auth_tag:
        raise HTTPException(status_code=401, detail="Unauthorized")
    if user.locked:
        raise HTTPException(status_code=403, detail="Account locked")
    return user

@router.post("/keypasses/save")
@limiter.limit("20/minute")
def save_keypass(request: Request, req: KeyPassCreate, db: Session= Depends(get_db)):
    user= authenticate_user(db, req.username, req.auth_tag)

    new_pass= KeyPass(
        user_id= user.id,
        nonce= req.nonce,
        ciphertext= req.cipher
    )

    db.add(new_pass)
    db.commit()
    db.refresh(new_pass)

    return {"message": "Passphrase saved!", "id": new_pass.id}

@router.post("/keypasses/sync")
@limiter.limit("10/minute")
def sync_vault(request: Request, req: LoginRequest, db: Session= Depends(get_db)):
    """Gets all the encrypted rows so that the user decrypts them locally"""

    user= authenticate_user(db, req.username, req.auth_tag)

    passes= db.query(KeyPass).filter(KeyPass.user_id== user.id).all()

    return{
        "vault": [
            {"id": p.id, "nonce": p.nonce, "ciphertext": p.ciphertext}
            for p in passes
        ]
    }
