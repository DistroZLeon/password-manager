from pydantic import BaseModel

class RegisterRequest(BaseModel):
    username: str
    salt: str
    auth_tag: str
    vk_nonce: str
    encrypted_vk: str

class LoginRequest(BaseModel):
    username: str
    auth_tag: str

class KeyPassCreate(BaseModel):
    username: str
    auth_tag: str
    nonce: str
    cipher: str
