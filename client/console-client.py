import re
import getpass
import requests
import secrets
import os
from dotenv import load_dotenv
from crypto import KeyDerivation, VaultSession

load_dotenv()
BASE_URL= os.getenv("BASE_URL", "http://127.0.0.1:8000")

def is_password_strong(password: str)-> bool:
    if len(password) < 12:
        return False  
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"\d", password):
        return False

    return True

def register():
    print("\n--- New Vault ---")
    username= input("Username: ")

    while True:
        print("\n[#] A strong pass must: \n- be longer than 12 characters\n- contain at least an UPPER character\n -contain at least a LOWER character\n - contain at least a number")
        password= getpass.getpass("Password: ")
        if is_password_strong(password):
            break
        print("\n[-] Weak Password!")
    cpassword= getpass.getpass("Confirm Password: ")

    if not secrets.compare_digest(password, cpassword):
        print("\n[-] Passwords don't match!")
        return

    pass_bytes= password.encode('utf-8')
    salt= os.urandom(16).hex()

    print("\n[*] Obtaining keys...")
    master_key= KeyDerivation.derive_master_key(pass_bytes, salt.encode('utf-8'))
    auth_tag= KeyDerivation.derive_auth_tag(master_key)

    session, vk_payload= VaultSession.create_vault(master_key)

    payload= {
        "username": username,
        "salt": salt,
        "auth_tag": auth_tag,
        "vk_nonce": vk_payload["vk_nonce"],
        "encrypted_vk": vk_payload["encrypted_vk"]
    }

    try:
        response= requests.post(f"{BASE_URL}/register", json= payload)
        response.raise_for_status()
        print("\n[*] Succesful registration!")
    except requests.exceptions.HTTPError as e:
        try:
            error_msg = e.response.json().get('detail', 'Unknown error')
        except ValueError:
            error_msg = e.response.text
        print(f"\n[-] Request failed: {error_msg}")

def login()-> VaultSession:
    print("\n--- Log in Vault ---")
    username= input("Username: ")

    try:
        salt_resp= requests.get(f"{BASE_URL}/users/{username}/salt")
        salt_resp.raise_for_status()
        salt= salt_resp.json()["salt"]
    except requests.exceptions.HTTPError:
        print("\nUser not found or server error!")
        return None

    password= getpass.getpass("Master Passphrase: ").encode('utf-8')
    print("Obtaining keys...")
    master_key= KeyDerivation.derive_master_key(password, salt.encode('utf-8'))
    auth_tag= KeyDerivation.derive_auth_tag(master_key)

    try:
        login_resp= requests.post(
            f"{BASE_URL}/login",
            json= {"username": username, "auth_tag": auth_tag}
        )
        login_resp.raise_for_status()
        data= login_resp.json()
    except requests.exceptions.HTTPError as e:
        try:
            error_msg = e.response.json().get('detail', 'Unknown error')
        except ValueError:
            error_msg = e.response.text
        print(f"\n[-] Request failed: {error_msg}")

    try:
        session= VaultSession.unlock_vault(
            master_key,
            data["vk_nonce"],
            data["encrypted_vk"]
        )
        print("\n[+] Logged in Vault!")
        return session
    except Exception as e:
        print(f"\n[-] Failed to decrypt vault: {e}")
        return None

def main():
    while True:
        print("\n1. Register. \n2. Login. \n3. Exit")
        choice = input("Select an option: ")
        
        if choice == '1':
            register()
        elif choice == '2':
            session = login()
            if session and session.is_active:
                print("Your session is active.")
                session.lock()
                print("[-] Vault locked!")
        elif choice == '3':
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()