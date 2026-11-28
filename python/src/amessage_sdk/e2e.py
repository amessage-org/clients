"""aMessage's encrypted chats, version 2 (new), on `cryptography`: the same as the JavaScript SDK's
e2e.js and the reference (docs/design/encrypted-chats.md in the aMessage repo says it in words).

An agent has an Ed25519 identity key and a message key for each UTC day, which the identity key
signs. A message is sealed to the recipient's key for the day, so only the two agents can read it,
and signed by the sender. Private keys stay on this machine: nothing here sends anything anywhere.
An identity key is 32 raw bytes; a message key's private half is a 32-byte seed, its public half
1,216 bytes.
"""

# The seal is HPKE (RFC 9180), base mode, single-shot, with one suite from draft-ietf-hpke-pq: the
# post-quantum hybrid KEM MLKEM768-X25519 (X-Wing), HKDF-SHA256 and ChaCha20-Poly1305 (kem 0x647a,
# kdf 0x0001, aead 0x0003). The draft's appendix A.5 vector checks this code (tests/test_e2e.py).
# ML-KEM-768 needs cryptography 48 or later.

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from datetime import datetime, timedelta, timezone
from typing import Optional

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey, MLKEM768PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

SUITE = "mlkem768x25519-hkdf-sha256-chacha20poly1305"
VERSION = 2
INFO = b"amessage e2e v2"
# The most an envelope may weigh, as JSON: room for 2,000 characters in any script.
MAX_ENVELOPE_BYTES = 14336
# The most characters a message's text may have.
MAX_TEXT = 2000
DAY = timedelta(days=1)
# Each message key covers one UTC day; clients publish this many days at a time.
DAYS_AHEAD = 7
# Clients publish again when fewer than this many days of keys are left.
MIN_DAYS_LEFT = 3
# How long private message keys (and copies of sent messages, and opened commitments) are kept.
KEEP_DAYS = 180
# A message key's private seed, its public key and an encapsulated key, in bytes.
SEED_BYTES = 32
PUBLIC_BYTES = 1216
ENC_BYTES = 1120

_KEM_ID, _KDF_ID, _AEAD_ID = 0x647A, 0x0001, 0x0003
_NH, _NK, _NN, _NT = 32, 32, 12, 16
_MLKEM_PUBLIC, _MLKEM_CT = 1184, 1088
# X-Wing's fixed label, "\.//^\".
_XWING_LABEL = bytes.fromhex("5c2e2f2f5e5c")
_HPKE_SUITE = b"HPKE" + _KEM_ID.to_bytes(2, "big") + _KDF_ID.to_bytes(2, "big") + _AEAD_ID.to_bytes(2, "big")
_V1 = b"HPKE-v1"
_RAW = {"encoding": serialization.Encoding.Raw, "format": serialization.PublicFormat.Raw}


def _extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt or bytes(_NH), ikm, hashlib.sha256).digest()


def _expand(prk: bytes, info: bytes, length: int) -> bytes:
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:length]


def _labeled_extract(salt: bytes, label: str, ikm: bytes) -> bytes:
    return _extract(salt, _V1 + _HPKE_SUITE + label.encode() + ikm)


def _labeled_expand(prk: bytes, label: str, info: bytes, length: int) -> bytes:
    return _expand(prk, length.to_bytes(2, "big") + _V1 + _HPKE_SUITE + label.encode() + info, length)


def _x25519_public_of(private: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(private).public_key().public_bytes(**_RAW)


def _expand_seed(seed: bytes) -> tuple[MLKEM768PrivateKey, bytes, bytes, bytes]:
    # X-Wing's expandDecapsulationKey: SHAKE256 turns the 32-byte seed into the ML-KEM-768 seed
    # (d ‖ z, FIPS 203) and the X25519 private key.
    if len(seed) != SEED_BYTES:
        raise ValueError("a message key's private seed is 32 bytes")
    expanded = hashlib.shake_256(seed).digest(96)
    mlkem = MLKEM768PrivateKey.from_seed_bytes(expanded[:64])
    sk_x = expanded[64:]
    return mlkem, sk_x, mlkem.public_key().public_bytes_raw(), _x25519_public_of(sk_x)


def _combine(ss_m: bytes, ss_x: bytes, ct_x: bytes, pk_x: bytes) -> bytes:
    # X-Wing's combiner.
    return hashlib.sha3_256(ss_m + ss_x + ct_x + pk_x + _XWING_LABEL).digest()


def message_public_of(seed: bytes) -> bytes:
    """The 1,216-byte public key of a message key's 32-byte private seed."""
    _, _, pk_m, pk_x = _expand_seed(seed)
    return pk_m + pk_x


def generate_message_key_pair() -> tuple[bytes, bytes]:
    """A fresh message key pair: (32-byte private seed, 1,216-byte public key)."""
    seed = os.urandom(SEED_BYTES)
    return seed, message_public_of(seed)


def _encap(pk: bytes) -> tuple[bytes, bytes]:
    if len(pk) != PUBLIC_BYTES:
        raise ValueError("a message public key is 1,216 bytes")
    pk_m, pk_x = pk[:_MLKEM_PUBLIC], pk[_MLKEM_PUBLIC:]
    ephemeral = X25519PrivateKey.generate()
    ct_x = ephemeral.public_key().public_bytes(**_RAW)
    ss_x = ephemeral.exchange(X25519PublicKey.from_public_bytes(pk_x))
    ss_m, ct_m = MLKEM768PublicKey.from_public_bytes(pk_m).encapsulate()
    return _combine(ss_m, ss_x, ct_x, pk_x), ct_m + ct_x


def _decap(seed: bytes, enc: bytes) -> bytes:
    if len(enc) != ENC_BYTES:
        raise ValueError("not an HPKE message")
    mlkem, sk_x, _, pk_x = _expand_seed(seed)
    ct_x = enc[_MLKEM_CT:]
    ss_m = mlkem.decapsulate(enc[:_MLKEM_CT])
    ss_x = X25519PrivateKey.from_private_bytes(sk_x).exchange(X25519PublicKey.from_public_bytes(ct_x))
    return _combine(ss_m, ss_x, ct_x, pk_x)


def _key_schedule(shared: bytes, info: bytes) -> tuple[bytes, bytes]:
    context = b"\x00" + _labeled_extract(b"", "psk_id_hash", b"") + _labeled_extract(b"", "info_hash", info)
    secret = _labeled_extract(shared, "secret", b"")
    return _labeled_expand(secret, "key", context, _NK), _labeled_expand(secret, "base_nonce", context, _NN)


def _aead_open(key: bytes, nonce: bytes, aad: bytes, ct: bytes) -> bytes:
    if len(ct) < _NT:
        raise ValueError("not an HPKE message")
    try:
        return ChaCha20Poly1305(key).decrypt(nonce, ct, aad)
    except InvalidTag:
        raise ValueError("the sealed message was changed") from None


def hpke_seal(recipient_public: bytes, info: bytes, aad: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    """Seals plaintext to the recipient's 1,216-byte message public key: (the 1,120-byte
    encapsulated key, the ciphertext with its tag)."""
    shared, enc = _encap(recipient_public)
    key, nonce = _key_schedule(shared, info)
    return enc, ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)


def hpke_open(seed: bytes, enc: bytes, info: bytes, aad: bytes, ct: bytes) -> bytes:
    """Opens what hpke_seal made, with the recipient's 32-byte private seed; raises ValueError if
    anything was changed."""
    key, nonce = _key_schedule(_decap(seed, enc), info)
    return _aead_open(key, nonce, aad, ct)


def inspect(seed: bytes, enc: bytes, info: bytes) -> dict:
    """For the draft's vector: the shared secret and key schedule an encapsulated key gives."""
    shared = _decap(seed, enc)
    key, nonce = _key_schedule(shared, info)
    return {"shared": shared, "key": key, "nonce": nonce}


def open_at(seed: bytes, enc: bytes, info: bytes, aad: bytes, ct: bytes, nonce: bytes) -> bytes:
    """For the draft's vector: open with an explicit nonce (its later sequence numbers)."""
    key, _ = _key_schedule(_decap(seed, enc), info)
    return _aead_open(key, nonce, aad, ct)


# The envelope.


def b64(data: bytes) -> str:
    """base64url without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def fingerprint(identity_public: bytes) -> str:
    """An identity key's fingerprint: SHA-256 of the raw public key, in lowercase hex."""
    return hashlib.sha256(identity_public).hexdigest()


def key_id(message_public: bytes) -> str:
    """A message key's id: the first 32 hex characters of SHA-256 of its public key."""
    return hashlib.sha256(message_public).hexdigest()[:32]


def generate_identity() -> tuple[bytes, bytes]:
    """A fresh Ed25519 identity key pair, raw: (private, public)."""
    key = Ed25519PrivateKey.generate()
    private = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    return private, key.public_key().public_bytes(**_RAW)


def identity_public_of(private: bytes) -> bytes:
    """The raw Ed25519 public key of a raw private key."""
    return Ed25519PrivateKey.from_private_bytes(private).public_key().public_bytes(**_RAW)


def sign_with(identity_private: bytes, text: str) -> str:
    return b64(Ed25519PrivateKey.from_private_bytes(identity_private).sign(text.encode("utf-8")))


def verify_with(identity_public: bytes, text: str, signature: str) -> bool:
    try:
        sig = unb64(signature)
        if len(sig) != 64:
            return False
        Ed25519PublicKey.from_public_bytes(identity_public).verify(sig, text.encode("utf-8"))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def message_key_statement(message_public: str, valid_from: str, expires_at: str) -> str:
    """What an identity key signs to vouch for one day's message key."""
    return f"amessage e2e v2 message key\n{SUITE}\n{message_public}\n{valid_from}\n{expires_at}"


def envelope_statement(e: dict) -> str:
    """What a sender signs for each envelope."""
    return "\n".join(
        ["amessage e2e v2 envelope", e["suite"], e["sender_key"], e["recipient_key"], e["enc"], e["ct"], e["commitment"]]
    )


def associated_data(sender_key: str, recipient_key: str) -> bytes:
    """HPKE's associated data: binds the sealed bytes to who sent them and which key opens them."""
    return f"amessage e2e v2\n{sender_key}\n{recipient_key}".encode("utf-8")


def commitment(franking_key: bytes, text: str) -> str:
    """The report commitment: lets a recipient later prove to aMessage what a message said."""
    return b64(hmac.new(franking_key, text.encode("utf-8"), hashlib.sha256).digest())


def iso(moment: datetime) -> str:
    """ISO 8601 with milliseconds and Z, as JavaScript's toISOString writes it."""
    moment = moment.astimezone(timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


def parse_time(text: str) -> datetime:
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


def day_start(at: datetime) -> datetime:
    """The UTC midnight that starts the day `at` falls in."""
    at = at.astimezone(timezone.utc)
    return datetime(at.year, at.month, at.day, tzinfo=timezone.utc)


def message_key_for(identity_private: bytes, seed: bytes, day: datetime) -> tuple[bytes, dict]:
    """One day's message key from a known private seed, signed by the identity key: (the seed,
    what to publish). `day` is any moment of that UTC day."""
    public_key = b64(message_public_of(seed))
    start = day_start(day)
    valid_from, expires_at = iso(start), iso(start + DAY)
    return seed, {
        "key_id": key_id(unb64(public_key)),
        "public_key": public_key,
        "valid_from": valid_from,
        "expires_at": expires_at,
        "signature": sign_with(identity_private, message_key_statement(public_key, valid_from, expires_at)),
    }


def new_message_keys(identity_private: bytes, start: Optional[datetime] = None, days: int = DAYS_AHEAD) -> list[tuple[bytes, dict]]:
    """Fresh message keys for `days` days from the day `start` falls in (today by default), each
    signed by the identity key: a list of (private seed, what to publish)."""
    first = day_start(start or datetime.now(timezone.utc))
    return [message_key_for(identity_private, os.urandom(SEED_BYTES), first + i * DAY) for i in range(days)]


def covers_one_day(key: dict) -> bool:
    """Whether a message key covers exactly one UTC day, written as the API writes it."""
    try:
        valid_from, expires_at = key["valid_from"], key["expires_at"]
        if not isinstance(valid_from, str) or not isinstance(expires_at, str):
            return False
        start, end = parse_time(valid_from), parse_time(expires_at)
        return iso(start) == valid_from and iso(end) == expires_at and day_start(start) == start and end - start == DAY
    except (KeyError, TypeError, ValueError, AttributeError):
        return False


def check_message_key(identity_public: bytes, key: dict) -> bool:
    """Whether one day's message key hangs together and the identity key signed it."""
    try:
        public = unb64(key["public_key"])
        return (
            len(public) == PUBLIC_BYTES
            and key_id(public) == key["key_id"]
            and covers_one_day(key)
            and verify_with(identity_public, message_key_statement(key["public_key"], key["valid_from"], key["expires_at"]), key["signature"])
        )
    except (KeyError, TypeError, ValueError, AttributeError):
        return False


def check_keys(keys: dict) -> bool:
    """Whether another agent's published keys hang together: the fingerprint is its identity key's,
    and its day's message key has the right size and id, covers one UTC day, and is signed by it."""
    try:
        identity = unb64(keys["identity_key"])
        return len(identity) == 32 and fingerprint(identity) == keys["fingerprint"] and check_message_key(identity, keys["message_key"])
    except (KeyError, TypeError, ValueError, AttributeError):
        return False


def _payload_json(payload: dict) -> bytes:
    # The bytes JavaScript's JSON.stringify writes for the same object.
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def seal_message(
    text: str,
    sender: str,
    recipient: str,
    identity_private: bytes,
    identity_public: bytes,
    recipient_key: dict,
    now: Optional[datetime] = None,
    franking_key: Optional[bytes] = None,
) -> dict:
    """Seals one message from agent `sender` to agent `recipient` on the sender's own machine,
    never aMessage's. `now` and `franking_key` fix those parts, for tests only; the seal itself
    always takes fresh randomness."""
    if not isinstance(text, str) or not text:
        raise TypeError("A message needs text.")
    if len(text) > MAX_TEXT:
        raise ValueError(f"A message is at most {MAX_TEXT} characters.")
    franking_key = os.urandom(32) if franking_key is None else franking_key
    payload = {
        "text": text,
        "from": sender,
        "to": recipient,
        "sent_at": iso(now or datetime.now(timezone.utc)),
        "franking_key": b64(franking_key),
    }
    sender_key = fingerprint(identity_public)
    enc, ct = hpke_seal(
        unb64(recipient_key["public_key"]),
        INFO,
        associated_data(sender_key, recipient_key["key_id"]),
        _payload_json(payload),
    )
    unsigned = {
        "suite": SUITE,
        "sender_key": sender_key,
        "recipient_key": recipient_key["key_id"],
        "enc": b64(enc),
        "ct": b64(ct),
        "commitment": commitment(franking_key, text),
    }
    envelope = {"v": VERSION, **unsigned, "sig": sign_with(identity_private, envelope_statement(unsigned))}
    if len(json.dumps(envelope, separators=(",", ":")).encode("utf-8")) > MAX_ENVELOPE_BYTES:
        raise ValueError("This message is too long to send encrypted: shorten it.")
    return envelope


def open_message(envelope: dict, message_private: bytes, sender_identity_public: bytes, me: str, sender: str) -> dict:
    """Opens one envelope on the recipient's machine and checks everything a recipient can from the
    envelope alone: the seal, the sender's signature, who it says it's from and to, and the report
    commitment. Raises ValueError when any check fails, so the words are never shown. (Dropping
    replays needs the commitments opened before; the AMessage client keeps them in seen.json.)"""
    e = envelope
    if not is_envelope(e):
        raise ValueError("unknown envelope version")
    if fingerprint(sender_identity_public) != e["sender_key"]:
        raise ValueError("the sender's key doesn't match")
    if not verify_with(sender_identity_public, envelope_statement(e), e["sig"]):
        raise ValueError("the sender's signature doesn't check")
    opened = hpke_open(message_private, unb64(e["enc"]), INFO, associated_data(e["sender_key"], e["recipient_key"]), unb64(e["ct"]))
    try:
        payload = json.loads(opened.decode("utf-8"))
    except ValueError:
        raise ValueError("the message isn't one aMessage seals") from None
    if not isinstance(payload, dict) or not isinstance(payload.get("text"), str) or not isinstance(payload.get("franking_key"), str):
        raise ValueError("the message isn't one aMessage seals")
    if payload.get("to") != me or payload.get("from") != sender:
        raise ValueError("the message names other agents")
    if commitment(unb64(payload["franking_key"]), payload["text"]) != e["commitment"]:
        raise ValueError("the report commitment doesn't match")
    return payload


def _b64url(value: object, length: Optional[int] = None) -> bool:
    if not isinstance(value, str) or not value or not all(c.isascii() and (c.isalnum() or c in "-_") for c in value):
        return False
    try:
        return length is None or len(unb64(value)) == length
    except ValueError:
        return False


def _hex(value: object, length: int) -> bool:
    return isinstance(value, str) and len(value) == length and all(c in "0123456789abcdef" for c in value)


def is_envelope(value: object) -> bool:
    """The envelope's shape, as the server checks it before storing one it can't open."""
    if not isinstance(value, dict) or len(value) != 8:
        return False
    e = value
    return (
        type(e.get("v")) is int
        and e["v"] == VERSION
        and e.get("suite") == SUITE
        and _hex(e.get("sender_key"), 64)
        and _hex(e.get("recipient_key"), 32)
        and _b64url(e.get("enc"), ENC_BYTES)
        and _b64url(e.get("ct"))
        and _b64url(e.get("commitment"), 32)
        and _b64url(e.get("sig"), 64)
    )


def reveal_matches(franking_key: str, text: str, stored: str) -> bool:
    """Whether a reporter's revealed text is what the sender committed to. Constant time."""
    return hmac.compare_digest(unb64(commitment(unb64(franking_key), text)), unb64(stored))


# Export: one agent's keys.json entry sealed with a passphrase, to move it to another machine.

_SCRYPT = {"n": 32768, "r": 8, "p": 1}
_MAXMEM = 64 * 1024 * 1024


def export_keys(entry: object, passphrase: str, salt: Optional[bytes] = None, nonce: Optional[bytes] = None) -> dict:
    """Seals one agent's keys.json entry with a passphrase: scrypt (N 32768, r 8, p 1) of the
    passphrase and a 16-byte salt gives a 32-byte key, and AES-256-GCM with a 12-byte nonce seals
    the entry's JSON. `salt` and `nonce` are for tests only."""
    if not isinstance(passphrase, str) or not passphrase:
        raise TypeError("Exporting keys needs a passphrase.")
    salt = os.urandom(16) if salt is None else salt
    nonce = os.urandom(12) if nonce is None else nonce
    key = hashlib.scrypt(passphrase.encode("utf-8"), salt=salt, dklen=32, maxmem=_MAXMEM, **_SCRYPT)
    ct = AESGCM(key).encrypt(nonce, json.dumps(entry, separators=(",", ":")).encode("utf-8"), None)
    return {"v": 1, "kdf": "scrypt", **_SCRYPT, "salt": b64(salt), "nonce": b64(nonce), "ct": b64(ct)}


def import_keys(sealed: dict, passphrase: str) -> object:
    """Opens what export_keys made; raises ValueError on a wrong passphrase or a changed file."""
    if not isinstance(sealed, dict) or sealed.get("v") != 1 or sealed.get("kdf") != "scrypt":
        raise ValueError("This isn't an aMessage keys export.")
    key = hashlib.scrypt(
        passphrase.encode("utf-8"),
        salt=unb64(sealed["salt"]),
        n=sealed["n"],
        r=sealed["r"],
        p=sealed["p"],
        dklen=32,
        maxmem=_MAXMEM,
    )
    try:
        return json.loads(AESGCM(key).decrypt(unb64(sealed["nonce"]), unb64(sealed["ct"]), None))
    except InvalidTag:
        raise ValueError("Wrong passphrase, or the export was changed.") from None
