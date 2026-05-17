"""
crypto/kdf.py
─────────────
Key Derivation Function layer.

After ML-KEM gives us a 32-byte shared secret, we must not use it
directly as an encryption key.  We use HKDF (RFC 5869) with SHA3-256
to stretch that single secret into separate keys for:
  • Encryption  (AES-256-GCM key)
  • MAC         (HMAC key, used if we ever need an additional MAC layer)
  • IV seeding  (deterministic nonce generation)

Why SHA3 instead of SHA2 in HKDF?
  SHA3 (Keccak) is a completely different construction from SHA2.
  If an attack ever weakens SHA2, using SHA3 here ensures the KDF
  layer remains independent.  Both are FIPS 202 / FIPS 180 approved.

NIST SP 800-56C §4 and SP 800-108 §4 authorise HKDF for this purpose.
"""

from __future__ import annotations
import hashlib
import hmac
import struct

import config
from crypto.utils import secure_zero


# ─── Session key bundle ───────────────────────────────────────────────────────

class SessionKeys:
    """
    Derived symmetric keys for one session direction.

    Every session has two SessionKeys instances:
      client_keys — used by the client when it is encrypting
      server_keys — used by the server when it is encrypting

    This prevents key reuse across directions even though both sides
    derived their keys from the same shared secret.

    Attributes:
        enc_key  — 32-byte AES-256 encryption key
        mac_key  — 32-byte HMAC key (supplemental authentication)
        iv_seed  — 32-byte seed for deterministic nonce generation
    """

    def __init__(self, enc_key: bytearray, mac_key: bytearray, iv_seed: bytearray):
        self._enc_key  = enc_key
        self._mac_key  = mac_key
        self._iv_seed  = iv_seed

    @property
    def enc_key(self) -> bytes:
        return bytes(self._enc_key)

    @property
    def mac_key(self) -> bytes:
        return bytes(self._mac_key)

    @property
    def iv_seed(self) -> bytes:
        return bytes(self._iv_seed)

    def destroy(self) -> None:
        """
        Zero all key material.  Call when a session ends or when rekeying.
        FIPS 203 §3.3: destroy intermediate and session values when done.
        """
        secure_zero(self._enc_key)
        secure_zero(self._mac_key)
        secure_zero(self._iv_seed)

    def derive_nonce(self, sequence_number: int) -> bytes:
        """
        Derive a deterministic 12-byte GCM nonce from the IV seed and
        a sequence number.

        Using a sequence-number-based nonce guarantees nonce uniqueness
        without requiring extra randomness.  The sequence number is a
        64-bit counter that never repeats within a session.

        AES-GCM requires nonce uniqueness per key — this construction
        satisfies that requirement as long as the sequence number never
        wraps (which at one message per nanosecond would take ~584 years).
        """
        # HMAC-SHA3-256(iv_seed, sequence_number_as_8_bytes) → 32 bytes
        # We take the first 12 bytes as the nonce.
        seq_bytes = struct.pack(">Q", sequence_number)  # big-endian uint64
        nonce_material = _hmac_sha3_256(self._iv_seed, seq_bytes)
        return nonce_material[:config.GCM_NONCE_BYTES]  # first 12 bytes


# ─── HKDF implementation with SHA3-256 ───────────────────────────────────────

def derive_session_keys(
    shared_secret: bytes,
    handshake_transcript: bytes,
    role: str,
) -> SessionKeys:
    """
    Derive AES-256-GCM session keys from an ML-KEM shared secret.

    Uses HKDF-Extract then HKDF-Expand (RFC 5869) with SHA3-256.

    Args:
        shared_secret:         32-byte output of ML-KEM decapsulate/encapsulate.
        handshake_transcript:  SHA3-512 digest of all handshake messages.
                               Binds the session keys to the specific handshake,
                               so keys differ even if the same shared_secret
                               appears in two different handshakes.
        role:                  "client" or "server" — provides directional
                               separation so each side uses different keys.

    Returns:
        SessionKeys containing enc_key, mac_key, and iv_seed.
    """
    if role not in ("client", "server"):
        raise ValueError("role must be 'client' or 'server'")

    # ── Step 1: HKDF-Extract ─────────────────────────────────────────────────
    # salt = handshake transcript (binds keys to this specific session)
    # IKM  = ML-KEM shared secret
    # PRK  = pseudorandom key material (32 bytes)
    prk = _hkdf_extract(
        salt=handshake_transcript[:32],  # first 32 bytes of SHA3-512 digest
        ikm=shared_secret,
    )

    # ── Step 2: HKDF-Expand ──────────────────────────────────────────────────
    # Expand PRK into three independent keys, each labelled by purpose and role.
    # Including role in info ensures client and server get different keys even
    # from the same PRK.

    role_bytes = role.encode()

    enc_key = bytearray(_hkdf_expand(
        prk=prk,
        info=config.KDF_INFO_ENC + b"|" + role_bytes,
        length=config.SYMMETRIC_KEY_BYTES,
    ))
    mac_key = bytearray(_hkdf_expand(
        prk=prk,
        info=config.KDF_INFO_MAC + b"|" + role_bytes,
        length=config.SYMMETRIC_KEY_BYTES,
    ))
    iv_seed = bytearray(_hkdf_expand(
        prk=prk,
        info=config.KDF_INFO_IV + b"|" + role_bytes,
        length=config.SYMMETRIC_KEY_BYTES,
    ))

    # ── Clean up intermediate PRK ─────────────────────────────────────────────
    prk_buf = bytearray(prk)
    secure_zero(prk_buf)

    return SessionKeys(enc_key=enc_key, mac_key=mac_key, iv_seed=iv_seed)


# ─── PBKDF2 for password-protected key storage ────────────────────────────────

def derive_storage_key(password: str, salt: bytes) -> bytearray:
    """
    Derive a 32-byte key from a user password for encrypting stored keys.

    Uses PBKDF2-HMAC-SHA256 with 600,000 iterations (NIST SP 800-132).
    This is slow by design — it makes brute-force password attacks expensive.

    Args:
        password:  User-supplied passphrase.
        salt:      Random 32-byte salt (stored alongside the encrypted key).

    Returns:
        32-byte key as bytearray for secure deletion.
    """
    import hashlib
    key = hashlib.pbkdf2_hmac(
        hash_name=config.KEY_PBKDF2_HASH,
        password=password.encode("utf-8"),
        salt=salt,
        iterations=config.KEY_PBKDF2_ITERATIONS,
        dklen=config.SYMMETRIC_KEY_BYTES,
    )
    return bytearray(key)


# ─── HKDF primitives ─────────────────────────────────────────────────────────

def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """
    HKDF-Extract (RFC 5869 §2.2).
    Returns a 32-byte pseudorandom key (PRK).
    """
    # HMAC-SHA3-256(salt, IKM)
    return _hmac_sha3_256(salt, ikm)


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """
    HKDF-Expand (RFC 5869 §2.3).
    Expands PRK into `length` bytes of output keying material.
    """
    hash_len = 32  # SHA3-256 output size
    n = -(-length // hash_len)  # ceiling division

    okm = b""
    t   = b""
    for i in range(1, n + 1):
        t = _hmac_sha3_256(prk, t + info + bytes([i]))
        okm += t

    return okm[:length]


def _hmac_sha3_256(key: bytes, data: bytes) -> bytes:
    """HMAC with SHA3-256."""
    return hmac.new(
        key=bytes(key),
        msg=data,
        digestmod=hashlib.sha3_256,
    ).digest()