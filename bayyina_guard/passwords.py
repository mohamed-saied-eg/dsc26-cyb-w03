"""Password storage for Bayyina's local break-glass accounts. Rules: README.md, "What to build", part 3."""
from __future__ import annotations

import hashlib
import hmac
import os
import unicodedata

# Current parameters required by the specification
CURRENT_N = 2**14
CURRENT_R = 8
CURRENT_P = 5
DKLEN = 32
SALT_LEN = 16


def hash_password(password: str) -> str:
    """scrypt$<n>$<r>$<p>$<salt>$<hash> with n=2**14, r=8, p=5, a 16-byte random salt, dklen=32."""
    if not isinstance(password, str):
        raise TypeError("Password must be a string")
        
    # Normalise password with NFKC and validate length limits (8-128 characters)
    normalized_pw = unicodedata.normalize("NFKC", password)
    if not (8 <= len(normalized_pw) <= 128):
        raise ValueError("Password must be between 8 and 128 characters")

    salt = os.urandom(SALT_LEN)
    salt_hex = salt.hex()
    
    # Generate scrypt hash using hashlib
    derived_key = hashlib.scrypt(
        normalized_pw.encode("utf-8"),
        salt=salt,
        n=CURRENT_N,
        r=CURRENT_R,
        p=CURRENT_P,
        dklen=DKLEN
    )
    hash_hex = derived_key.hex()
    
    return f"scrypt${CURRENT_N}${CURRENT_R}${CURRENT_P}${salt_hex}${hash_hex}"


def verify_password(password: str, stored: str) -> bool:
    """True only if `password` matches `stored`. Never raises: anything malformed is False."""
    try:
        if not isinstance(password, str) or not isinstance(stored, str) or not stored.startswith("scrypt$"):
            return False
            
        # Normalise input password for verification as well
        normalized_pw = unicodedata.normalize("NFKC", password)
        if not (8 <= len(normalized_pw) <= 128):
            return False

        parts = stored.split("$")
        if len(parts) != 6:
            return False
            
        _, n_str, r_str, p_str, salt_hex, hash_hex = parts
        
        n = int(n_str)
        r = int(r_str)
        p = int(p_str)
        
        # Security bounds checks
        if not (2 <= n <= 2**20 and (n & (n - 1)) == 0):
            return False
        if not (1 <= r <= 32):
            return False
        if not (1 <= p <= 16):
            return False
            
        salt = bytes.fromhex(salt_hex)
        if len(salt) < 16:
            return False
            
        expected_hash = bytes.fromhex(hash_hex)
        if len(expected_hash) != 32:
            return False
        
        # Compute hash with the stored parameters
        derived_key = hashlib.scrypt(
            normalized_pw.encode("utf-8"),
            salt=salt,
            n=n,
            r=r,
            p=p,
            dklen=len(expected_hash)
        )
        
        # Constant-time comparison to prevent timing side-channel attacks
        return hmac.compare_digest(derived_key, expected_hash)
    except Exception:
        return False


def needs_rehash(stored: str) -> bool:
    """True if `stored` cannot be parsed or any of n, r, p is below the current values."""
    try:
        if not isinstance(stored, str) or not stored.startswith("scrypt$"):
            return True
            
        parts = stored.split("$")
        if len(parts) != 6:
            return True
            
        _, n_str, r_str, p_str, _, _ = parts
        
        n = int(n_str)
        r = int(r_str)
        p = int(p_str)
        
        # Check if any parameter is below current required values
        if n < CURRENT_N or r < CURRENT_R or p < CURRENT_P:
            return True
            
        return False
    except Exception:
        return True