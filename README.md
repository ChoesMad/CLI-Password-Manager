A secure Command Line Interface (CLI) tool built with Python to manage your credentials locally. It uses industry-standard encryption to ensure your data stays private.

Security Features
AES-256 Encryption: All passwords are encrypted using the cryptography (Fernet) library.

Master Password Hashing: Uses PBKDF2 with a unique salt to verify the master password without storing it in plain text.

Local Storage: Data is stored in a local SQLite database (vault.db).
