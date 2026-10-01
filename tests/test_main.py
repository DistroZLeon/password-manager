import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from dependencies import get_db, limiter
from main import app
from models import Base

limiter.enabled= False

SQLALCHEMY_DATABASE_URL= "sqlite:///:memory:"

engine= create_engine(
    SQLALCHEMY_DATABASE_URL, 
    connect_args= {"check_same_thread": False},
    poolclass= StaticPool
)
TestingSessionLocal= sessionmaker(autocommit= False, autoflush= False, bind= engine)

# Override the get_db dependency to use the test database instead of vault.db
def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db]= override_get_db
client= TestClient(app)

# Reset the database before EVERY test
@pytest.fixture(autouse= True)
def setup_and_teardown_db():
    Base.metadata.create_all(bind= engine)
    yield
    Base.metadata.drop_all(bind= engine)

# --- TESTS ---

def test_register_user_success():
    response= client.post(
        "/users/register",
        json= {
            "username": "username",
            "salt": "randomsalt123",
            "auth_tag": "validauthtag",
            "vk_nonce": "nonce123",
            "encrypted_vk": "encryptedkey123"
        }
    )
    assert response.status_code== 200
    assert response.json()== {"message": "User registered!"}

def test_register_duplicate_user_fails():
    payload= {
        "username": "username",
        "salt": "randomsalt123",
        "auth_tag": "validauthtag",
        "vk_nonce": "nonce123",
        "encrypted_vk": "encryptedkey123"
    }
    # Register once
    client.post("/users/register", json= payload)
    
    response = client.post("/users/register", json= payload)
    assert response.status_code== 400
    assert response.json()["detail"]== "Username already registered!"

def test_get_salt_success():
    client.post(
        "/users/register",
        json= {
            "username": "username",
            "salt": "randomsalt123",
            "auth_tag": "validauthtag",
            "vk_nonce": "nonce123",
            "encrypted_vk": "encryptedkey123"
        }
    )
    response = client.get("/users/username/salt")
    assert response.status_code== 200
    assert response.json()["salt"]== "randomsalt123"

def test_get_salt_not_found():
    response = client.get("/users/ghost/salt")
    assert response.status_code== 404

def test_login_success():
    client.post(
        "/users/register",
        json= {
            "username": "username",
            "salt": "randomsalt123",
            "auth_tag": "validauthtag",
            "vk_nonce": "nonce123",
            "encrypted_vk": "encryptedkey123"
        }
    )
    
    # Attempt login
    response= client.post(
        "/users/login",
        json= {"username": "username", "auth_tag": "validauthtag"}
    )
    assert response.status_code== 200
    
    # Ensure it returns the cryptographic vault data
    data= response.json()
    assert data["vk_nonce"]== "nonce123"
    assert data["encrypted_vk"]== "encryptedkey123"

def test_login_failure_triggers_lockout():
    client.post(
        "/users/register",
        json= {
            "username": "username",
            "salt": "randomsalt123",
            "auth_tag": "validauthtag",
            "vk_nonce": "nonce",
            "encrypted_vk": "key"
        }
    )
    
    # Fail 5 times in a row
    for _ in range(5):
        response= client.post(
            "/users/login",
            json= {"username": "username", "auth_tag": "WRONG_TAG"}
        )
        assert response.status_code== 401
        assert response.json()["detail"]== "Invalid credentials"
        
    # The 6th attempt should return the lockout message, even if the tag is still wrong
    response = client.post(
        "/users/login",
        json= {"username": "username", "auth_tag": "WRONG_TAG"}
    )
    assert response.status_code== 401
    assert response.json()["detail"]== "Account locked"

def test_unlock_account_restores_access():
    # Register and lock out a user
    client.post("/users/register", json={
        "username": "lockeduser", "salt": "salt123", "auth_tag": "validtag", 
        "vk_nonce": "n", "encrypted_vk": "c"
    })
    
    for _ in range(5):
        client.post("/users/login", json={"username": "lockeduser", "auth_tag": "wrong_tag"})
        
    # Verify account is fully locked
    res_locked = client.post("/users/login", json={"username": "lockeduser", "auth_tag": "wrong_tag"})
    assert res_locked.json()["detail"] == "Account locked"
    
    # Unlock the account with the correct auth_tag
    res_unlock = client.post("/users/unlock", json={"username": "lockeduser", "auth_tag": "validtag"})
    assert res_unlock.status_code == 200
    
    # Verify normal login works again
    res_login = client.post("/users/login", json={"username": "lockeduser", "auth_tag": "validtag"})
    assert res_login.status_code == 200

def test_keypass_crud_lifecycle():
    # Setup User
    client.post("/users/register", json={
        "username": "vaultuser", "salt": "s", "auth_tag": "tag", 
        "vk_nonce": "n", "encrypted_vk": "c"
    })
    
    # Create
    save_res = client.post("/keypasses/save", json={
        "username": "vaultuser", "auth_tag": "tag", "nonce": "nonce1", "cipher": "cipher1"
    })
    assert save_res.status_code == 200
    pass_id = save_res.json()["id"]
    
    # Read
    sync_res = client.post("/keypasses/sync", json={"username": "vaultuser", "auth_tag": "tag"})
    assert sync_res.status_code == 200
    vault = sync_res.json()["vault"]
    assert len(vault) == 1
    assert vault[0]["id"] == pass_id
    
    # Update
    update_res = client.put(f"/keypasses/{pass_id}/update", json={
        "username": "vaultuser", "auth_tag": "tag", "nonce": "nonce2", "cipher": "cipher2"
    })
    assert update_res.status_code == 200
    
    # Verify Update
    sync_updated = client.post("/keypasses/sync", json={"username": "vaultuser", "auth_tag": "tag"})
    assert sync_updated.json()["vault"][0]["ciphertext"] == "cipher2"
    
    # Delete
    delete_res = client.request(
            "DELETE",
            f"/keypasses/{pass_id}/delete", 
            json={"username": "vaultuser", "auth_tag": "tag"}
        )
    assert delete_res.status_code == 200
    
    # Verify Deletion
    sync_empty = client.post("/keypasses/sync", json={"username": "vaultuser", "auth_tag": "tag"})
    assert len(sync_empty.json()["vault"]) == 0