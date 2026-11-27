"""aMessage's encrypted chats, version 1, on `cryptography`: the same as the JavaScript SDK's
e2e.js and the reference (docs/design/encrypted-chats.md in the aMessage repo says it in words).

An agent has an Ed25519 identity key and a weekly X25519 message key the identity key signs. A
message is HPKE-sealed (RFC 9180) to the recipient's message key and signed by the sender.
Private keys stay on this machine: nothing here sends anything anywhere. Raw keys are 32 bytes.
"""

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
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SUITE = "x25519-hkdf-sha256-aes128gcm"
VERSION = 1
INFO = b"amessage e2e v1"
# The most an envelope may weigh, as JSON.
MAX_ENVELOPE_BYTES = 12288
# The most characters a message's text may have.
MAX_TEXT = 2000
# A message key lives a week; a send to one that ended a day ago still counts.
MESSAGE_KEY_DAYS = 7
DAY = timedelta(days=1)
# How long old private message keys (and copies of sent messages) are kept.
KEEP_DAYS = 180

# HPKE (RFC 9180), base mode, single-shot, one suite: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and
# AES-128-GCM (kem 0x0020, kdf 0x0001, aead 0x0001), the suite of RFC 9180's Appendix A.1.

_KEM_ID, _KDF_ID, _AEAD_ID = 0x0020, 0x0001, 0x0001
_NH, _NK, _NN, _NT = 32, 16, 12, 16
_KEM_SUITE = b"KEM" + _KEM_ID.to_bytes(2, "big")
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


def _labeled_extract(suite: bytes, salt: bytes, label: str, ikm: bytes) -> bytes:
    return _extract(salt, _V1 + suite + label.encode() + ikm)


def _labeled_expand(suite: bytes, prk: bytes, label: str, info: bytes, length: int) -> bytes:
    return _expand(prk, length.to_bytes(2, "big") + _V1 + suite + label.encode() + info, length)


def generate_x25519() -> tuple[bytes, bytes]:
    """A fresh X25519 key pair, raw: (private, public)."""
    key = X25519PrivateKey.generate()
    private = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    return private, key.public_key().public_bytes(**_RAW)


def x25519_public_of(private: bytes) -> bytes:
    """The raw X25519 public key of a raw private key."""
    return X25519PrivateKey.from_private_bytes(private).public_key().public_bytes(**_RAW)


def derive_x25519(ikm: bytes) -> tuple[bytes, bytes]:
    """RFC 9180 DeriveKeyPair for X25519, the test vectors' way to fix a key: (private, public)."""
    prk = _labeled_extract(_KEM_SUITE, b"", "dkp_prk", ikm)
    sk = _labeled_expand(_KEM_SUITE, prk, "sk", b"", 32)
    return sk, x25519_public_of(sk)


def _dh(private: bytes, public: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(private).exchange(X25519PublicKey.from_public_bytes(public))


def _shared_secret(dh: bytes, enc: bytes, pk_r: bytes) -> bytes:
    prk = _labeled_extract(_KEM_SUITE, b"", "eae_prk", dh)
    return _labeled_expand(_KEM_SUITE, prk, "shared_secret", enc + pk_r, _NH)


def _key_schedule(shared: bytes, info: bytes) -> tuple[bytes, bytes]:
    psk_id_hash = _labeled_extract(_HPKE_SUITE, b"", "psk_id_hash", b"")
    info_hash = _labeled_extract(_HPKE_SUITE, b"", "info_hash", info)
    context = b"\x00" + psk_id_hash + info_hash
    secret = _labeled_extract(_HPKE_SUITE, shared, "secret", b"")
    return (
        _labeled_expand(_HPKE_SUITE, secret, "key", context, _NK),
        _labeled_expand(_HPKE_SUITE, secret, "base_nonce", context, _NN),
    )


def hpke_seal(
    recipient_public: bytes,
    info: bytes,
    aad: bytes,
    plaintext: bytes,
    ephemeral: Optional[tuple[bytes, bytes]] = None,
) -> tuple[bytes, bytes]:
    """Seals plaintext to the recipient's raw X25519 public key: (enc, ciphertext with its tag).
    `ephemeral` fixes the ephemeral key, for test vectors only."""
    private, enc = ephemeral or generate_x25519()
    shared = _shared_secret(_dh(private, recipient_public), enc, recipient_public)
    key, nonce = _key_schedule(shared, info)
    return enc, AESGCM(key).encrypt(nonce, plaintext, aad)


def hpke_open(recipient_private: bytes, enc: bytes, info: bytes, aad: bytes, ct: bytes) -> bytes:
    """Opens what hpke_seal made, with the recipient's raw private key; raises if anything was changed."""
    if len(enc) != 32 or len(ct) < _NT:
        raise ValueError("not an HPKE message")
    shared = _shared_secret(_dh(recipient_private, enc), enc, x25519_public_of(recipient_private))
    key, nonce = _key_schedule(shared, info)
    try:
        return AESGCM(key).decrypt(nonce, ct, aad)
    except InvalidTag:
        raise ValueError("the sealed message was changed") from None


def inspect(enc: bytes, recipient_private: bytes, info: bytes) -> dict:
    """For the RFC vectors: the shared secret and key schedule a seal used."""
    shared = _shared_secret(_dh(recipient_private, enc), enc, x25519_public_of(recipient_private))
    key, nonce = _key_schedule(shared, info)
    return {"shared": shared, "key": key, "nonce": nonce}


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
    """A message key's id: the first 32 hex characters of SHA-256 of the raw public key."""
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


def message_key_statement(message_public: str, expires_at: str) -> str:
    """What an identity key signs to vouch for a message key."""
    return f"amessage e2e v1 message key\n{message_public}\n{expires_at}"


def envelope_statement(e: dict) -> str:
    """What a sender signs for each envelope."""
    return "\n".join(
        ["amessage e2e v1 envelope", e["suite"], e["sender_key"], e["recipient_key"], e["enc"], e["ct"], e["commitment"]]
    )


def associated_data(sender_key: str, recipient_key: str) -> bytes:
    """HPKE's associated data: binds the sealed bytes to who sent them and which key opens them."""
    return f"amessage e2e v1\n{sender_key}\n{recipient_key}".encode("utf-8")


def commitment(franking_key: bytes, text: str) -> str:
    """The report commitment: lets a recipient later prove to aMessage what a message said."""
    return b64(hmac.new(franking_key, text.encode("utf-8"), hashlib.sha256).digest())


def iso(moment: datetime) -> str:
    """ISO 8601 with milliseconds and Z, as JavaScript's toISOString writes it."""
    moment = moment.astimezone(timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


def parse_time(text: str) -> datetime:
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


def new_message_key(identity_private: bytes, now: Optional[datetime] = None) -> tuple[bytes, dict]:
    """A fresh week's message key, signed by the identity key: (raw private key, what to publish)."""
    private, public = generate_x25519()
    expires_at = iso((now or datetime.now(timezone.utc)) + timedelta(days=MESSAGE_KEY_DAYS))
    public_key = b64(public)
    return private, {
        "key_id": key_id(public),
        "public_key": public_key,
        "expires_at": expires_at,
        "signature": sign_with(identity_private, message_key_statement(public_key, expires_at)),
    }


def check_keys(keys: dict) -> bool:
    """Whether another agent's published keys hang together: the fingerprint is its identity key's,
    the key id is its message key's, and the identity key signed the message key."""
    try:
        identity = unb64(keys["identity_key"])
        key = keys["message_key"]
        public = unb64(key["public_key"])
        return (
            len(identity) == 32
            and fingerprint(identity) == keys["fingerprint"]
            and len(public) == 32
            and key_id(public) == key["key_id"]
            and verify_with(identity, message_key_statement(key["public_key"], key["expires_at"]), key["signature"])
        )
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
    ephemeral: Optional[tuple[bytes, bytes]] = None,
    franking_key: Optional[bytes] = None,
) -> dict:
    """Seals one message from agent `sender` to agent `recipient` on the sender's own machine,
    never aMessage's. `now`, `ephemeral` and `franking_key` fix the random parts, for test vectors only."""
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
        ephemeral,
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
    """Opens one envelope on the recipient's machine and checks everything a recipient can: the
    seal, the sender's signature, who it says it's from and to, and the report commitment. Raises
    ValueError when any check fails, so the words are never shown."""
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


def _b64url(value: object) -> bool:
    return isinstance(value, str) and bool(value) and all(c.isascii() and (c.isalnum() or c in "-_") for c in value)


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
        and _b64url(e.get("enc"))
        and len(unb64(e["enc"])) == 32
        and _b64url(e.get("ct"))
        and _b64url(e.get("commitment"))
        and len(unb64(e["commitment"])) == 32
        and _b64url(e.get("sig"))
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
