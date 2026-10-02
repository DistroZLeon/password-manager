import os
import base64
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

class KeyDerivation:
    """Cryptographic functions for key derivation"""

    @staticmethod
    def derive_master_key(master_password: bytes, salt: bytes)-> bytes:
        """Derives Master Key from Master Passphrase using Argon2"""
        
        return hash_secret_raw(
            secret=master_password,
            salt=salt,
            time_cost=3,
            memory_cost=65536,
            parallelism=4,
            hash_len=32,
            type=Type.ID
        )

    @staticmethod
    def derive_auth_tag(master_key: bytes)-> bytes:
        """Derives auth tag for server verification"""

        hkdf= HKDF(
            algorithm= hashes.SHA256(),
            length= 32,
            salt= b"server-auth-salt",
            info= b"auth-tag-derivation"
        )

        return base64.b64encode(hkdf.derive(master_key)).decode('utf-8')

class VaultSession:
    """Active vault state"""

    def __init__(self, rvault_key: bytes):
        self.rvault_key= bytearray(rvault_key)
        self.cipher= AESGCM(bytes(self.rvault_key))
        self.is_active= True

    @classmethod
    def create_vault(cls, master_key: bytes)-> tuple["VaultSession", dict]:
        """
        Used only during account creation
        Creates a new vault key
        """

        rvault_key= AESGCM.generate_key(bit_length= 256)

        master_cipher= AESGCM(master_key)
        nonce= os.urandom(12)
        encrypted_vk= master_cipher.encrypt(nonce, rvault_key, None)

        vk_payload= {
            "vk_nonce": base64.b64encode(nonce).decode('utf-8'),
            "encrypted_vk": base64.b64encode(encrypted_vk).decode('utf-8')
        }

        return cls(rvault_key), vk_payload

    @classmethod
    def unlock_vault(cls, master_key: bytes, vk_nonce_b64: str, encryted_vk_b64: str)-> "VaultSession":
        """
        For login
        Decrypts the stored vault key
        """

        master_cipher= AESGCM(master_key)
        nonce= base64.b64decode(vk_nonce_b64)
        encrypted_vk= base64.b64decode(encryted_vk_b64)

        rvault_key= master_cipher.decrypt(nonce, encrypted_vk, None)
        return cls(rvault_key)

    def encrypt_entry(self, plaintext: str)-> dict:
        """Encrypt entry data"""

        if not self.is_active:
            raise RuntimeError("Vault is not active")

        nonce= os.urandom(12)
        cipher= self.cipher.encrypt(nonce, plaintext.encode('utf-8'), None)

        return{
            "nonce": base64.b64encode(nonce).decode('utf-8'),
            "ciphertext": base64.b64encode(cipher).decode('utf-8')
        }

    def decrypt_entry(self, nonce_b64: str, ciphertext_b64: str)-> str:
        """Decrypt entry"""

        if not self.is_active:
            raise RuntimeError("Vault is not active")

        nonce= base64.b64decode(nonce_b64)
        cipher= base64.b64decode(ciphertext_b64)

        return self.cipher.decrypt(nonce, cipher, None).decode('utf-8')

    def lock(self):
        """Deactivates the current session"""

        for i in range(len(self.rvault_key)):
            self.rvault_key[i]= 0

        self.cipher= None
        self.is_active= False

