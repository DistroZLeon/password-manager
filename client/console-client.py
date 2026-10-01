import re
import getpass
import json
import requests
import secrets
import os
from dotenv import load_dotenv
from crypto import KeyDerivation, VaultSession
from api import VaultAPI

load_dotenv()
BASE_URL= os.getenv("BASE_URL", "http://127.0.0.1:8000")
api = VaultAPI(BASE_URL)

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

def handle_api_error(e):
    if hasattr(e, 'response') and e.response is not None:
        try:
            error_msg = e.response.json().get('detail', 'Unknown error')
        except Exception:
            error_msg = e.response.text
    else:
        error_msg = str(e) 
    print(f"\n[-] Request failed: {error_msg}")

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
        api.register(payload)
        print("\n[*] Successful registration!")
    except Exception as e:
        handle_api_error(e)

def login()-> tuple[VaultSession, str, str]:
    print("\n--- Log in Vault ---")
    username= input("Username: ")

    try:
        salt_resp= requests.get(f"{BASE_URL}/users/{username}/salt")
        salt_resp.raise_for_status()
        salt= salt_resp.json()["salt"]
    except requests.exceptions.HTTPError:
        print("\nUser not found or server error!")
        return None, None, None

    password= getpass.getpass("Master Passphrase: ").encode('utf-8')
    print("Obtaining keys...")
    master_key= KeyDerivation.derive_master_key(password, salt.encode('utf-8'))
    auth_tag= KeyDerivation.derive_auth_tag(master_key)

    try:
        data= api.login(username, auth_tag)
        session= VaultSession.unlock_vault(
            master_key,
            data["vk_nonce"],
            data["encrypted_vk"]
        )
        print("\n[+] Logged in Vault!")
        return session, username, auth_tag
    except Exception as e:
        handle_api_error(e)
        return None, None, None

def unlock_account():
    print("\n--- Unlock Account ---")
    username= input("Username: ")
    try:
        salt= api.get_salt(username)
    except Exception:
        print("\n[-] User not found or error")
        return

    password= getpass.getpass("Passphrase: ").encode('utf-8')
    master_key= KeyDerivation.derive_master_key(password, salt.encode('utf-8'))
    auth_tag= KeyDerivation.derive_auth_tag(master_key)

    try:
        api.unlock_account(username, auth_tag)
        print("\n[+] Account unlocked!")
    except Exception as e:
        handle_api_error(e)

def vault_menu(session: VaultSession, username: str, auth_tag: str):
    """Vault sub-menu"""
    while True:
        print("\n--- Vault Actions --")
        print("1. Add a pass")
        print("2. View a pass")
        print("3. Edit a pass")
        print("4. Delete a pass")
        print("5. Logout")
        choice= input("Select the option: ")

        if choice== "1":
            name= input("Name: ")
            url= input("URL: ")
            acc_user= input("Account username: ")
            acc_pass= getpass.getpass("Account password: ")

            data= json.dumps({
                "name": name,
                "url": url,
                "username": acc_user,
                "password": acc_pass
            })

            enc= session.encrypt_entry(data)
            try:
                api.save_keypass(username, auth_tag, enc["nonce"], enc["ciphertext"])
                print("\n[+] Password saved!")
            except Exception as e:
                handle_api_error(e)

        elif choice== "2":
            try:
                enc_rows= api.sync_vault(username, auth_tag)
                print(f"\n[*] Obtained {len(enc_rows)} rows!")

                for row in enc_rows:
                    djson= session.decrypt_entry(row["nonce"], row["ciphertext"])
                    data= json.loads(djson)

                    print(f"\n--- {data.get('name', 'Unknown')} ---")
                    print(f"Id:       {row["id"]}")
                    print(f"URL:      {data.get('url', '')}")
                    print(f"Username: {data.get('username', '')}")
                    print(f"Password: {data.get('password', '')}")
                    print("-" * 25)
            except Exception as e:
                handle_api_error(e)

        elif choice== "3":
            passId= input("Id of the Password: ")
            name= input("Name: ")
            url= input("URL: ")
            acc_user= input("Account username: ")
            acc_pass= getpass.getpass("Account password: ")

            data= json.dumps({
                            "name": name,
                            "url": url,
                            "username": acc_user,
                            "password": acc_pass
                        })
            edata= session.encrypt_entry(data)

            try:
                api.update_keypass(passId, username, auth_tag, edata["nonce"], edata["ciphertext"])
                print("\n[+] Password updated!")
            except Exception as e:
                handle_api_error(e)

        elif choice== "4":
            passId= input("Id of the Password: ")
            try:
                api.delete_keypass(passId, username, auth_tag)
                print("\n[+] Password deleted!")
            except Exception as e:
                handle_api_error(e)

        elif choice== "5":
            session.lock()
            print("[-] Vault locked!")
            break
        else:
            print("[#] Invalid option")

def main():
    while True:
        print("\n1. Register. \n2. Login. \n3. Unlock \n4. Exit")
        choice = input("Select an option: ")
        
        if choice== '1':
            register()
        elif choice== '2':
            session, username, auth_tag = login()
            if session and session.is_active:
                print("Your session is active.")
                vault_menu(session, username, auth_tag)
        elif choice== "3":
            unlock_account()
        elif choice== '4':
            break
        else:
            print("Invalid choice.")

if __name__== "__main__":
    main()