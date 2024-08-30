#!/usr/bin/env python3
"""Password Encryption Module"""

import bcrypt


def hash_password(password: str) -> bytes:
    """Random Password Hashing"""

    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """Hashedpw/Dycreptedpw Compatibility Check"""

    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
