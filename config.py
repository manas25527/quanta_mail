"""
config.py
─────────
Central configuration for the entire PQ Messenger system.
All algorithm names, sizes, and tuning parameters live here so
you only ever change one file when switching parameter sets.

FIPS references:
  ML-KEM   → FIPS 203, Table 2 & 3
  ML-DSA   → FIPS 204, Table 1 & 2
  SLH-DSA  → FIPS 205, Table 2
"""

import os
from dotenv import load_dotenv

load_dotenv()  # lets you override anything via a .env file

# ─── ML-KEM (Key Encapsulation) ───────────────────────────────────────────────
# FIPS 203 §8: three parameter sets; 768 is NIST's recommended default.
KEM_ALGORITHM       = "ML-KEM-768"
KEM_ENCAP_KEY_BYTES = 1184   # public encapsulation key size
KEM_DECAP_KEY_BYTES = 2400   # private decapsulation key size
KEM_CIPHERTEXT_BYTES= 1088   # KEM ciphertext size
KEM_SHARED_SECRET_BYTES = 32 # always 32 bytes for all ML-KEM variants

# ─── ML-DSA (Digital Signatures for identities & messages) ────────────────────
# FIPS 204 §4: ML-DSA-65 → security category 3, same level as ML-KEM-768.
DSA_ALGORITHM       = "ML-DSA-65"
DSA_PUBLIC_KEY_BYTES  = 1952
DSA_PRIVATE_KEY_BYTES = 4032
DSA_SIGNATURE_BYTES   = 3309

# Context strings for ML-DSA domain separation (FIPS 204 §5.2).
# Using different ctx values ensures a signature for one purpose cannot
# be replayed in a different context even with the same key.
DSA_CTX_HANDSHAKE   = b"pq-messenger-handshake-v1"
DSA_CTX_CERTIFICATE = b"pq-messenger-certificate-v1"
DSA_CTX_MESSAGE     = b"pq-messenger-message-v1"

# ─── SLH-DSA proxy via SPHINCS+ (long-lived CA signatures) ───────────────────
# FIPS 205 §11: liboqs exposes this as SPHINCS+-SHAKE-192s-simple
# which is the simple (non-robust) variant of SLH-DSA-SHAKE-192s.
# Security category 3.  Used ONLY for certificate signing — not messages.
SLHDSA_ALGORITHM          = "SPHINCS+-SHAKE-192s-simple"
SLHDSA_PUBLIC_KEY_BYTES   = 48
SLHDSA_PRIVATE_KEY_BYTES  = 96
SLHDSA_SIGNATURE_BYTES    = 16224

# ─── Symmetric encryption (bulk message data) ─────────────────────────────────
# AES-256-GCM: 256-bit key defeats Grover's √N quantum speedup on block ciphers.
# Grover halves security bits → 256-bit key gives 128-bit post-quantum security.
SYMMETRIC_KEY_BYTES = 32  # 256 bits
GCM_NONCE_BYTES     = 12  # 96-bit nonce (GCM standard)
GCM_TAG_BYTES       = 16  # 128-bit authentication tag

# ─── Key Derivation ───────────────────────────────────────────────────────────
# HKDF with SHA3-256 keeps the KDF layer also quantum-resistant.
KDF_HASH       = "sha3-256"
KDF_INFO_ENC   = b"pq-messenger-enc-key-v1"
KDF_INFO_MAC   = b"pq-messenger-mac-key-v1"
KDF_INFO_IV    = b"pq-messenger-iv-seed-v1"

# ─── Session policy ───────────────────────────────────────────────────────────
# FIPS 203 §3.3: destroy intermediate values; rotate session keys regularly.
SESSION_REKEY_AFTER_MESSAGES = 1000
SESSION_REKEY_AFTER_SECONDS  = 3600   # 1 hour

# ─── Key storage (encrypted at rest) ─────────────────────────────────────────
KEY_STORAGE_DIR        = os.getenv("PQ_KEY_DIR", "./keys")
KEY_PBKDF2_ITERATIONS  = 600_000   # NIST SP 800-132 recommendation
KEY_PBKDF2_HASH        = "sha256"
KEY_SALT_BYTES         = 32

# ─── Server ───────────────────────────────────────────────────────────────────
SERVER_HOST = os.getenv("PQ_SERVER_HOST", "127.0.0.1")
SERVER_PORT = int(os.getenv("PQ_SERVER_PORT", "8000"))