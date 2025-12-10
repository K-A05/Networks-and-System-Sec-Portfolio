import re
from typing import Dict, Tuple, Optional

import bcrypt
import pyotp

# Mock in-memory user database
# Structure: users[username] = { 'password_hash': b'...', 'totp_secret': 'BASE32' }
users: Dict[str, Dict[str, bytes]] = {}


def analyze_password_strength(password: str, username: Optional[str] = None) -> Tuple[bool, str]:
    """Return (is_strong, reason). Basic checks:
    - at least 12 characters
    - has lower, upper, digit, special
    - not equal to username
    - not a common password (very small built-in list)
    """
    if username and password.lower() == username.lower():
        return False, "password must not be the same as the username"

    if len(password) < 12:
        return False, "password must be at least 12 characters"

    checks = [
        (re.search(r"[a-z]", password), "lowercase letter"),
        (re.search(r"[A-Z]", password), "uppercase letter"),
        (re.search(r"\d", password), "digit"),
        (re.search(r"[^A-Za-z0-9]", password), "special character"),
    ]

    missing = [name for ok, name in checks if not ok]
    if missing:
        return False, f"password must include: {', '.join(missing)}"

    # Check against a small list of common passwords
    try:
        with open("passwds.txt", "r") as f:
            common_passwords = {line.strip().lower() for line in f}
        if password.lower() in common_passwords:
            return False, "password is too common"
    except FileNotFoundError:
        print("Warning: error performing common password check, proceed with caution.")
        pass  # If the file is not found, skip this check

    return True, ""


def register_user(username: str, password: str) -> Dict[str, str]:
    """Register a new user.

    Steps:
    1) Analyze password strength and reject weak passwords.
    2) Securely hash the password (bcrypt, salt embedded).
    3) Create a TOTP secret using `pyotp`.
    4) Store the password hash and totp secret in `users` (mock DB).

    Returns the stored record (for demonstration).
    Raises ValueError for invalid inputs or existing user.
    """
    if username in users:
        raise ValueError("user already exists")

    ok, reason = analyze_password_strength(password, username=username)
    if not ok:
        raise ValueError(f"weak password: {reason}")

    # bcrypt generates a salt automatically and embeds it in the hashed result
    password_bytes = password.encode("utf-8")
    password_hash = bcrypt.hashpw(password_bytes, bcrypt.gensalt())

    # Generate TOTP secret (base32)
    totp_secret = pyotp.random_base32()

    # Store in mock DB
    users[username] = {
        "password_hash": password_hash,
        "totp_secret": totp_secret,
    }

    return {"username": username, "password_hash": password_hash.decode(), "totp_secret": totp_secret}


def authenticate(username: str, password: str) -> bool:
    """Authenticate a user by verifying the password.

    This uses `bcrypt.checkpw`, which internally extracts the salt
    from the stored hash and performs a secure comparison.
    Returns True on success, False otherwise.
    """
    record = users.get(username)
    if not record:
        return False

    stored_hash = record["password_hash"]
    # stored_hash might be bytes or str depending on storage; ensure bytes
    if isinstance(stored_hash, str):
        stored_hash = stored_hash.encode()

    try:
        return bcrypt.checkpw(password.encode("utf-8"), stored_hash)
    except Exception:
        return False


def get_totp_uri(username: str, issuer_name: str = "ExampleApp") -> Optional[str]:
    """Return the otpauth URI for provisioning (can be used to create QR codes).
    Returns None if user not found.
    """
    record = users.get(username)
    if not record:
        return None
    secret = record["totp_secret"]
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=username, issuer_name=issuer_name)
