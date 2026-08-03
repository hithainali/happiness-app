from passlib.context import CryptContext
from typing import Tuple
import logging

from db import get_user_by_username, create_user
from config import ADMIN_PASSWORD

pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_ctx.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return pwd_ctx.verify(password, password_hash)
    except Exception:
        logging.exception("Password verification failed")
        return False


def register_user(username: str, password: str) -> Tuple[bool, str]:
    # basic validation
    if len(username) < 3 or len(password) < 5:
        return False, "Username must be 3+ chars and password 5+ chars"

    hashed = hash_password(password)
    success = create_user(username, hashed)
    if success:
        return True, "Account created successfully"
    return False, "Username already exists"


def authenticate(username: str, password: str) -> bool:
    row = get_user_by_username(username)
    if row and verify_password(password, row["password_hash"]):
        return True
    return False


def init_admin() -> None:
    # If admin already exists, nothing to do.
    if get_user_by_username("admin"):
        return

    if ADMIN_PASSWORD:
        success = create_user("admin", hash_password(ADMIN_PASSWORD))
        if success:
            print("Admin account created from ADMIN_PASSWORD environment variable.")
        else:
            print("Failed to create admin user. Might already exist.")
    else:
        # Do not create a default insecure admin. Inform the operator.
        print(
            "No admin user found and ADMIN_PASSWORD not set. To create an admin user, set the ADMIN_PASSWORD environment variable before first run."
        )
