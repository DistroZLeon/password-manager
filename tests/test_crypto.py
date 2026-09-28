import pytest
from crypto import KeyDerivation, VaultSession

def test_key_consistency():
    master_password = b"VerySecretMasterPassword123."
    salt = b"unique_user_salt_1234"

    # Derive master key twice with same inputs
    mk1 = KeyDerivation.derive_master_key(master_password, salt)
    mk2 = KeyDerivation.derive_master_key(master_password, salt)

    assert mk1 == mk2, "Master Key derivation must be deterministic!"

    # Ensure auth hash derivation works and is consistent
    auth1 = KeyDerivation.derive_auth_tag(mk1)
    auth2 = KeyDerivation.derive_auth_tag(mk2)

    assert auth1 == auth2, "Auth hash must be deterministic!"
    assert auth1 != mk1.decode('utf-8', errors='ignore'), "Auth hash must never equal Master Key!"


def test_vault_creation_and_unlock():
    master_password = b"MyMasterPassword"
    salt = b"random_salt"
    master_key = KeyDerivation.derive_master_key(master_password, salt)

    # 1. Simulate account creation on Device A
    session_a, encrypted_vk_payload = VaultSession.create_vault(master_key)
    assert session_a.is_active is True

    # 2. Simulate login on Device B
    session_b = VaultSession.unlock_vault(
        master_key,
        encrypted_vk_payload["vk_nonce"],
        encrypted_vk_payload["encrypted_vk"]
    )
    assert session_b.is_active is True

    # Test that both sessions can decrypt each other's data
    entry = session_a.encrypt_entry("my_secret_bank_password")
    decrypted_by_b = session_b.decrypt_entry(entry["nonce"], entry["ciphertext"])

    assert decrypted_by_b == "my_secret_bank_password"


def test_session_lock():
    master_key = b"0" * 32
    session, _ = VaultSession.create_vault(master_key)

    session.lock()
    assert session.is_active is False

    with pytest.raises(RuntimeError):
        session.encrypt_entry("data")