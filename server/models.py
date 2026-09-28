from sqlalchemy import Column, Integer, Boolean, String, ForeignKey, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
import uuid

def generate_uuid():
    return str(uuid.uuid4())

Base= declarative_base()

class User(Base):
    __tablename__= "users"

    id= Column(String, primary_key= True, index= True, default= generate_uuid)
    username= Column(String, unique= True, index= True, nullable= False)

    salt= Column(String, nullable= False)
    auth_tag= Column(String, nullable= False)

    vk_nonce= Column(String, nullable= False)
    encrypted_vk= Column(String, nullable= False)

    locked= Column(Boolean, default= False)
    failed_attempts= Column(Integer, default= 0)

    passes= relationship("KeyPass", back_populates= "owner")

class KeyPass(Base):
    __tablename__= "key_passes"

    id= Column(String, primary_key= True, index= True, default= generate_uuid)
    user_id= Column(String, ForeignKey("users.id"), nullable= False)

    nonce= Column(String, nullable= False)
    ciphertext= Column(String, nullable= False)

    owner= relationship("User", back_populates= "passes")

engine= create_engine("sqlite:///./vault.db", connect_args= {"check_same_thread": False})
SessionLocal= sessionmaker(autocommit= False, autoflush= False, bind= engine)
Base.metadata.create_all(bind= engine)