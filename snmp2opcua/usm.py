"""SNMPv3 User-based Security Model crypto.

* Key derivation and localization: RFC 3414 A.2 (MD5/SHA-1), RFC 7860 (SHA-2)
* Authentication: HMAC-MD5-96, HMAC-SHA-96, HMAC-SHA-224/256/384/512 (RFC 3414, RFC 7860)
* Privacy: DES-CBC (RFC 3414 8), AES-128-CFB (RFC 3826), AES-192/256-CFB with either
  Blumenthal key extension (net-snmp "AES-192"/"AES-256") or Reeder key extension
  (Cisco and net-snmp "AES-192-C"/"AES-256-C")

Hashing and HMAC come from the standard library. Encryption needs the ``cryptography``
package, which asyncua already depends on.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import struct
from dataclasses import dataclass, field


class UsmError(ValueError):
    """Authentication/decryption problem with an SNMPv3 message."""


# name -> (hash constructor, truncated MAC length)
AUTH_PROTOCOLS = {
    "MD5": (hashlib.md5, 12),
    "SHA": (hashlib.sha1, 12),
    "SHA224": (hashlib.sha224, 16),
    "SHA256": (hashlib.sha256, 24),
    "SHA384": (hashlib.sha384, 32),
    "SHA512": (hashlib.sha512, 48),
}
# name -> (cipher key length, key extension method)
PRIV_PROTOCOLS = {
    "DES": (8, None),
    "AES": (16, None),
    "AES192": (24, "blumenthal"),
    "AES256": (32, "blumenthal"),
    "AES192C": (24, "reeder"),
    "AES256C": (32, "reeder"),
}
_ALIASES = {"SHA1": "SHA", "AES128": "AES", "NOAUTH": "NONE", "NOPRIV": "NONE", "": "NONE"}


def normalize(name: str | None) -> str:
    n = str(name or "NONE").upper().replace("-", "").replace("_", "")
    return _ALIASES.get(n, n)


def password_to_key(password: bytes, hashfn) -> bytes:
    """RFC 3414 A.2: hash 1 MiB of the repeated password."""
    if not password:
        raise ValueError("empty SNMPv3 password")
    size = 1048576
    stream = (password * (size // len(password) + 1))[:size]
    return hashfn(stream).digest()


def localize_key(ku: bytes, engine_id: bytes, hashfn) -> bytes:
    """RFC 3414 2.6: Kul = H(Ku || snmpEngineID || Ku)."""
    return hashfn(ku + engine_id + ku).digest()


# --------------------------------------------------------------------------
# Authentication
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class AuthProtocol:
    name: str

    @property
    def hashfn(self):
        return AUTH_PROTOCOLS[self.name][0]

    @property
    def mac_len(self) -> int:
        return AUTH_PROTOCOLS[self.name][1]

    def mac(self, key: bytes, message: bytes) -> bytes:
        return hmac.new(key, message, self.hashfn).digest()[: self.mac_len]

    def verify(self, key: bytes, message: bytes, mac: bytes) -> bool:
        return hmac.compare_digest(self.mac(key, message), mac)


# --------------------------------------------------------------------------
# Privacy
# --------------------------------------------------------------------------
def _ciphers():
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError as exc:  # pragma: no cover
        raise UsmError("SNMPv3 privacy needs the 'cryptography' package (pip install cryptography)") from exc
    try:  # moved out of the main namespace in cryptography 43+
        from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
    except ImportError:  # pragma: no cover
        from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES
    return Cipher, algorithms, modes, TripleDES


def _xor(a: bytes, b: bytes) -> bytes:
    n = len(a)
    return (int.from_bytes(a, "big") ^ int.from_bytes(b[:n], "big")).to_bytes(n, "big")


def _aes_cfb128(key: bytes, iv: bytes, data: bytes, decrypt: bool) -> bytes:
    """AES-CFB128 built on AES-ECB, so it works on every cryptography version."""
    Cipher, algorithms, modes, _ = _ciphers()
    ecb = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    out = bytearray()
    feedback = iv
    for i in range(0, len(data), 16):
        block = data[i:i + 16]
        result = _xor(block, ecb.update(feedback))
        out += result
        feedback = block if decrypt else result
    return bytes(out)


_salt_counter = int.from_bytes(os.urandom(8), "big")


def _next_salt() -> int:
    global _salt_counter
    _salt_counter = (_salt_counter + 1) & 0xFFFFFFFFFFFFFFFF
    return _salt_counter


@dataclass(frozen=True)
class PrivProtocol:
    name: str

    @property
    def key_len(self) -> int:
        return PRIV_PROTOCOLS[self.name][0]

    def localize(self, priv_ku: bytes, engine_id: bytes, hashfn) -> bytes:
        kul = localize_key(priv_ku, engine_id, hashfn)
        needed = 16 if self.name == "DES" else self.key_len  # DES uses 8 key + 8 pre-IV bytes
        method = PRIV_PROTOCOLS[self.name][1]
        while len(kul) < needed:
            if method == "blumenthal":
                kul += hashfn(kul).digest()
            elif method == "reeder":
                kul += localize_key(password_to_key(kul, hashfn), engine_id, hashfn)
            else:
                raise UsmError(f"{self.name} needs a longer key than the auth hash provides")
        return kul[:needed]

    def encrypt(self, key: bytes, boots: int, engine_time: int, plaintext: bytes) -> tuple[bytes, bytes]:
        """Returns (ciphertext, msgPrivacyParameters)."""
        Cipher, algorithms, modes, TripleDES = _ciphers()
        if self.name == "DES":
            salt = struct.pack(">II", boots & 0xFFFFFFFF, _next_salt() & 0xFFFFFFFF)
            iv = _xor(key[8:16], salt)
            pad = (-len(plaintext)) % 8
            enc = Cipher(TripleDES(key[:8] * 3), modes.CBC(iv)).encryptor()
            return enc.update(plaintext + b"\x00" * pad) + enc.finalize(), salt
        salt = struct.pack(">Q", _next_salt())
        iv = struct.pack(">II", boots, engine_time) + salt
        return _aes_cfb128(key[: self.key_len], iv, plaintext, decrypt=False), salt

    def decrypt(self, key: bytes, boots: int, engine_time: int, priv_params: bytes, ciphertext: bytes) -> bytes:
        if len(priv_params) != 8:
            raise UsmError("msgPrivacyParameters must be 8 octets")
        Cipher, algorithms, modes, TripleDES = _ciphers()
        if self.name == "DES":
            if len(ciphertext) % 8:
                raise UsmError("DES ciphertext is not a multiple of 8 octets")
            iv = _xor(key[8:16], priv_params)
            dec = Cipher(TripleDES(key[:8] * 3), modes.CBC(iv)).decryptor()
            return dec.update(ciphertext) + dec.finalize()
        iv = struct.pack(">II", boots, engine_time) + priv_params
        return _aes_cfb128(key[: self.key_len], iv, ciphertext, decrypt=True)


# --------------------------------------------------------------------------
# Users
# --------------------------------------------------------------------------
@dataclass
class UsmUser:
    name: str
    auth: AuthProtocol | None = None
    priv: PrivProtocol | None = None
    auth_ku: bytes = b""
    priv_ku: bytes = b""
    engine_ids: frozenset = frozenset()          # allowed sender engine IDs for traps (empty = any)
    _priv_cache: dict = field(default_factory=dict, repr=False)

    @classmethod
    def create(cls, name: str, auth_protocol: str | None = None, auth_key: str | None = None,
               priv_protocol: str | None = None, priv_key: str | None = None,
               engine_ids: list[str] | None = None) -> "UsmUser":
        if not name:
            raise ValueError("SNMPv3 user needs a name")
        a, p = normalize(auth_protocol), normalize(priv_protocol)
        if a != "NONE" and a not in AUTH_PROTOCOLS:
            raise ValueError(f"user {name}: unknown auth_protocol {auth_protocol!r}; use one of "
                             f"{', '.join(AUTH_PROTOCOLS)} or NONE")
        if p != "NONE" and p not in PRIV_PROTOCOLS:
            raise ValueError(f"user {name}: unknown priv_protocol {priv_protocol!r}; use one of "
                             f"{', '.join(PRIV_PROTOCOLS)} or NONE")
        if p != "NONE" and a == "NONE":
            raise ValueError(f"user {name}: privacy requires authentication (authPriv)")
        user = cls(name=name)
        if a != "NONE":
            if not auth_key or len(auth_key) < 8:
                raise ValueError(f"user {name}: auth_key must be at least 8 characters")
            user.auth = AuthProtocol(a)
            user.auth_ku = password_to_key(auth_key.encode("utf-8"), user.auth.hashfn)
        if p != "NONE":
            if not priv_key or len(priv_key) < 8:
                raise ValueError(f"user {name}: priv_key must be at least 8 characters")
            user.priv = PrivProtocol(p)
            user.priv_ku = password_to_key(priv_key.encode("utf-8"), user.auth.hashfn)
        user.engine_ids = frozenset(bytes.fromhex(e.replace(":", "").replace(" ", ""))
                                    for e in (engine_ids or []))
        return user

    @property
    def level(self) -> str:
        return "authPriv" if self.priv else ("authNoPriv" if self.auth else "noAuthNoPriv")

    def auth_key(self, engine_id: bytes) -> bytes:
        return localize_key(self.auth_ku, engine_id, self.auth.hashfn)

    def priv_key(self, engine_id: bytes) -> bytes:
        """Localized privacy key; cached because Reeder extension costs a 1 MiB hash.
        Only call this after the message authenticated, so spoofed engine IDs can't fill the cache."""
        key = self._priv_cache.get(engine_id)
        if key is None:
            key = self.priv.localize(self.priv_ku, engine_id, self.auth.hashfn)
            if len(self._priv_cache) > 1024:
                self._priv_cache.clear()
            self._priv_cache[engine_id] = key
        return key
