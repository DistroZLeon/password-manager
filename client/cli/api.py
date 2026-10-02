import requests

class VaultAPI:
    def __init__(self, base_url: str):
        self.base_url= base_url

    def get_salt(self, username: str)-> str:
        res= requests.get(f"{self.base_url}/users/{username}/salt")
        res.raise_for_status()
        return res.json()["salt"]

    def register(self, payload: dict):
        res= requests.post(f"{self.base_url}/users/register", json= payload)
        res.raise_for_status()

    def login(self, username: str, auth_tag: str)-> dict:
        res= requests.post(
            f"{self.base_url}/users/login",
            json={"username": username, "auth_tag": auth_tag}
        )
        res.raise_for_status()
        return res.json()

    def save_keypass(self, username: str, auth_tag: str, nonce: str, ciphertext: str):
        payload={
            "username": username,
            "auth_tag": auth_tag,
            "nonce": nonce,
            "cipher": ciphertext
        }

        res= requests.post(f"{self.base_url}/keypasses/save", json= payload)
        res.raise_for_status()
        return res.json()

    def sync_vault(self, username: str, auth_tag: str)-> list:
        res= requests.post(f"{self.base_url}/keypasses/sync", json= {"username": username, "auth_tag": auth_tag})
        res.raise_for_status()
        return res.json()["vault"]

    def update_keypass(self, passId: str, username: str, auth_tag: str, nonce: str, cipher: str):
        payload= {"username": username, "auth_tag": auth_tag, "nonce": nonce, "cipher": cipher}
        res= requests.put(
            f"{self.base_url}/keypasses/{passId}/update",
            json= payload
        )
        res.raise_for_status()
        return res.json()

    def delete_keypass(self, passId: str, username: str, auth_tag: str):
        res= requests.delete(
            f"{self.base_url}/keypasses/{passId}/delete",
                        json= {"username": username, "auth_tag": auth_tag}
        )
        res.raise_for_status()
        return res.json()

    def unlock_account(self, username: str, auth_tag: str):
        payload= {"username": username, "auth_tag": auth_tag}
        res= requests.post(f"{self.base_url}/users/unlock", json= payload)
        res.raise_for_status()
        return res.json()