"""
crypto/kem.py
─────────────
ML-KEM-768 wrapper (FIPS 203).

What this module does:
  • Generates ephemeral KEM key pairs for each session.
  • Encapsulates (produces a shared secret + ciphertext from an encap key).
  • Decapsulates (recovers shared secret from a ciphertext + decap key).
  • Enforces mandatory input checking from FIPS 203 §7.2 and §7.3.
  • Destroys secret material after use.

ML-KEM flow reminder:
  Alice runs KeyGen → gets (encap_key, decap_key)
  Alice sends encap_key to Bob.
  Bob runs Encaps(encap_key) → gets (shared_secret, ciphertext)
  Bob sends ciphertext to Alice.
  Alice runs Decaps(decap_key, ciphertext) → gets shared_secret
  Both now share the same 32-byte secret.
"""

from __future__ import annotations
import oqs
from dataclasses import dataclass
from typing import Optional

import config
from crypto.utils import (
    secure_zero,
    constant_time_compare,
    random_bytes,
    public_key_fingerprint,
)


# ─── Data classes ─────────────────────────────────────────────────────────────

@dataclass
class KEMKeyPair:
    """
    Holds an ephemeral ML-KEM key pair.

    encap_key  – send this to the remote peer (public, 1184 bytes)
    decap_key  – keep this secret (private, 2400 bytes) stored as bytearray
                 so we can securely zero it after use.
    """
    encap_key: bytes          # public — safe to transmit
    _decap_key: bytearray     # private — MUST call destroy() when done

    @property
    def decap_key(self) -> bytes:
        return bytes(self._decap_key)

    def destroy(self) -> None:
        """
        Zero the private decapsulation key in memory.
        Call this as soon as you have derived the session key from it.
        FIPS 203 §3.3: only the designated output may be retained.
        """
        secure_zero(self._decap_key)

    @property
    def fingerprint(self) -> str:
        return public_key_fingerprint(self.encap_key)


@dataclass
class EncapsulationResult:
    """
    Output of encapsulation.

    shared_secret  – 32 bytes, use as input to HKDF
    ciphertext     – 1088 bytes, send to the decapsulating party
    """
    shared_secret: bytearray  # stored as bytearray for secure deletion
    ciphertext: bytes         # safe to transmit

    def destroy(self) -> None:
        """Zero the shared secret once the session key has been derived."""
        secure_zero(self.shared_secret)


# ─── Core functions ───────────────────────────────────────────────────────────

def generate_keypair() -> KEMKeyPair:
    """
    Generate a fresh ML-KEM-768 key pair.

    This should be called once per session (ephemeral keys).
    Never reuse a decapsulation key across sessions — forward secrecy
    depends on discarding it after one use.

    Returns:
        KEMKeyPair with encap_key (public) and decap_key (private).
    """
    kem = oqs.KeyEncapsulation(config.KEM_ALGORITHM)
    encap_key: bytes = kem.generate_keypair()
    decap_key: bytes = kem.export_secret_key()

    # Validate sizes against FIPS 203 Table 3
    _assert_size("encap_key", encap_key, config.KEM_ENCAP_KEY_BYTES)
    _assert_size("decap_key", decap_key, config.KEM_DECAP_KEY_BYTES)

    return KEMKeyPair(
        encap_key=encap_key,
        _decap_key=bytearray(decap_key),
    )


def encapsulate(encap_key: bytes) -> EncapsulationResult:
    """
    Encapsulate: given the remote party's public encapsulation key,
    produce a shared secret and ciphertext.

    Performs the encapsulation key check required by FIPS 203 §7.2:
      1. Type check   – correct byte length for the parameter set.
      2. Modulus check – all encoded integers must be in [0, q-1].

    Args:
        encap_key: the remote party's ML-KEM-768 encapsulation key.

    Returns:
        EncapsulationResult containing shared_secret and ciphertext.

    Raises:
        ValueError if the encapsulation key fails input checking.
    """
    # FIPS 203 §7.2 Input Check 1: type check
    _check_encap_key(encap_key)

    kem = oqs.KeyEncapsulation(config.KEM_ALGORITHM)
    ciphertext, shared_secret = kem.encap_secret(encap_key)

    _assert_size("ciphertext",    ciphertext,    config.KEM_CIPHERTEXT_BYTES)
    _assert_size("shared_secret", shared_secret, config.KEM_SHARED_SECRET_BYTES)

    return EncapsulationResult(
        shared_secret=bytearray(shared_secret),
        ciphertext=ciphertext,
    )


def decapsulate(decap_key: bytes, ciphertext: bytes) -> bytearray:
    """
    Decapsulate: recover the shared secret from a ciphertext using the
    private decapsulation key.

    Performs the decapsulation input checks from FIPS 203 §7.3:
      1. Ciphertext type check – correct byte length.
      2. Decapsulation key type check – correct byte length.

    Implicit rejection (FIPS 203 §6.3):
      liboqs implements this internally. If the ciphertext is invalid,
      decapsulation returns a pseudorandom value instead of an error.
      Your protocol detects tampering through GCM authentication tag
      failure on the first encrypted message, not through this function.

    Args:
        decap_key:  the private ML-KEM-768 decapsulation key.
        ciphertext: the ciphertext received from the encapsulating party.

    Returns:
        shared_secret as bytearray (32 bytes). Caller must call
        secure_zero() on it after deriving the session key.

    Raises:
        ValueError if inputs fail size checks.
    """
    # FIPS 203 §7.3 Input Checks
    _check_decap_inputs(decap_key, ciphertext)

    kem = oqs.KeyEncapsulation(config.KEM_ALGORITHM, secret_key=decap_key)
    shared_secret: bytes = kem.decap_secret(ciphertext)

    _assert_size("shared_secret", shared_secret, config.KEM_SHARED_SECRET_BYTES)

    return bytearray(shared_secret)


# ─── Input validation helpers ─────────────────────────────────────────────────

def _check_encap_key(encap_key: bytes) -> None:
    """
    FIPS 203 §7.2 encapsulation key checks.

    Check 1 – Type check: length must be exactly 384k+32 for k=3 (ML-KEM-768).
    Check 2 – Modulus check: we rely on liboqs to enforce this internally.
              A pure-Python modulus check would require implementing
              ByteEncode12/ByteDecode12, which liboqs handles for us.
    """
    if not isinstance(encap_key, (bytes, bytearray)):
        raise ValueError("encap_key must be bytes or bytearray")
    if len(encap_key) != config.KEM_ENCAP_KEY_BYTES:
        raise ValueError(
            f"encap_key length must be {config.KEM_ENCAP_KEY_BYTES} bytes, "
            f"got {len(encap_key)}"
        )


def _check_decap_inputs(decap_key: bytes, ciphertext: bytes) -> None:
    """FIPS 203 §7.3 decapsulation input checks."""
    if len(ciphertext) != config.KEM_CIPHERTEXT_BYTES:
        raise ValueError(
            f"ciphertext length must be {config.KEM_CIPHERTEXT_BYTES} bytes, "
            f"got {len(ciphertext)}"
        )
    if len(decap_key) != config.KEM_DECAP_KEY_BYTES:
        raise ValueError(
            f"decap_key length must be {config.KEM_DECAP_KEY_BYTES} bytes, "
            f"got {len(decap_key)}"
        )


def _assert_size(name: str, data: bytes, expected: int) -> None:
    if len(data) != expected:
        raise RuntimeError(
            f"Internal error: {name} has unexpected size "
            f"(got {len(data)}, expected {expected}). "
            "This indicates a bug or library mismatch."
        )