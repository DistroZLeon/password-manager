import pytest
import responses
from requests.exceptions import HTTPError

from api import VaultAPI

@pytest.fixture
def api_client():
    return VaultAPI("http://mock-server.local")

@responses.activate
def test_get_salt_success(api_client):
    # Instruct the mock to intercept this specific URL
    responses.add(
        responses.GET,
        "http://mock-server.local/users/username/salt",
        json= {"salt": "fake_random_salt_890"},
        status= 200
    )
    
    # Execute your code
    salt= api_client.get_salt("username")
    
    # Assert your code parsed the JSON correctly
    assert salt== "fake_random_salt_890"

@responses.activate
def test_get_salt_not_found(api_client):
    responses.add(
        responses.GET,
        "http://mock-server.local/users/ghost/salt",
        json= {"detail": "User not found!"},
        status= 404
    )
    
    with pytest.raises(HTTPError):
        api_client.get_salt("ghost")

@responses.activate
def test_login_success(api_client):
    responses.add(
        responses.POST,
        "http://mock-server.local/users/login",
        json= {
            "salt": "fake_salt",
            "vk_nonce": "fake_nonce",
            "encrypted_vk": "fake_ciphertext"
        },
        status= 200
    )
    
    data= api_client.login("username", "valid_auth_tag")
    assert data["vk_nonce"]== "fake_nonce"
    assert data["encrypted_vk"]== "fake_ciphertext"

@responses.activate
def test_save_keypass_success(api_client):
    responses.add(
        responses.POST,
        "http://mock-server.local/keypasses/save",
        json= {"message": "Saved successfully", "id": "uuid-1234"},
        status= 200
    )
    
    result= api_client.save_keypass("username", "auth_tag", "nonce123", "cipher123")
    assert result["id"]== "uuid-1234"

@responses.activate
def test_sync_vault_success(api_client):
    mock_vault_data= {
        "vault": [
            {"id": "1", "nonce": "n1", "ciphertext": "c1"},
            {"id": "2", "nonce": "n2", "ciphertext": "c2"}
        ]
    }
    
    responses.add(
        responses.POST,
        "http://mock-server.local/keypasses/sync",
        json= mock_vault_data,
        status= 200
    )
    
    vault= api_client.sync_vault("username", "auth_tag")
    assert len(vault)== 2
    assert vault[0]["ciphertext"]== "c1"