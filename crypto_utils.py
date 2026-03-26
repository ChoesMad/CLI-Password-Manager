import os
import base64
import hmac
from typing import Optional

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet, InvalidToken

PBKDF2_ITERATIONS: int = 390_000
KEY_LENGTH: int = 32

def generate_salt(length: int = 32) -> bytes:
    return os.urandom(length)

def hash_password(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend(),
    )
    return kdf.derive(password.encode("utf-8"))


def verify_password(password: str, salt: bytes, stored_hash: bytes) -> bool:
    candidate_hash = hash_password(password, salt)
    return hmac.compare_digest(candidate_hash, stored_hash)

class VaultCipher:
    def __init__(self, master_password: str, salt: bytes) -> None:
        self._fernet = Fernet(self._derive_fernet_key(master_password, salt))

    @staticmethod
    def _derive_fernet_key(master_password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_LENGTH,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
            backend=default_backend(),
        )
        raw_key = kdf.derive(master_password.encode("utf-8"))
        return base64.urlsafe_b64encode(raw_key)

    def encrypt(self, plaintext: str) -> bytes:
        return self._fernet.encrypt(plaintext.encode("utf-8"))

    def decrypt(self, token: bytes) -> Optional[str]:
        try:
            return self._fernet.decrypt(token).decode("utf-8")
        except InvalidToken:
            raise InvalidToken("Invalid token or incorrect Master Password.")
