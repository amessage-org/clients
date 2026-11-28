import json
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse
from uuid import uuid4

from amessage_sdk import AMessage, AMessageError, EncryptionError, e2e

ROOT = Path(__file__).resolve().parents[2]
VECTORS = json.loads((ROOT / "test-vectors" / "encrypted-chats-vectors.json").read_text("utf-8"))
API = "https://api.amessage.sh"

HEX = bytes.fromhex
U = e2e.unb64


def _node_version() -> tuple:
    node = shutil.which("node")
    if not node:
        return ()
    out = subprocess.run([node, "--version"], capture_output=True, text=True).stdout.strip().lstrip("v")
    return tuple(int(part) for part in out.split(".")[:2])


# The JavaScript SDK needs Node 24.7 or later (built-in ML-KEM).
HAS_NODE = _node_version() >= (24, 7)


class BuildingBlocksTest(unittest.TestCase):
    def test_matches_draft_ietf_hpke_pq_a5(self):
        h = VECTORS["hpke"]
        sk = HEX(h["skRm"])
        self.assertEqual(e2e.message_public_of(sk).hex(), h["pkRm"])
        schedule = e2e.inspect(sk, HEX(h["enc"]), HEX(h["info"]))
        self.assertEqual(schedule["shared"].hex(), h["shared_secret"])
        self.assertEqual(schedule["key"].hex(), h["key"])
        self.assertEqual(schedule["nonce"].hex(), h["base_nonce"])
        self.assertEqual(len(h["encryptions"]), 2)
        for m in h["encryptions"]:
            opened = e2e.open_at(sk, HEX(h["enc"]), HEX(h["info"]), HEX(m["aad"]), HEX(m["ct"]), HEX(m["nonce"]))
            self.assertEqual(opened.hex(), m["pt"])
        first = h["encryptions"][0]
        # The first message is the one a single-shot open reads, with the base nonce.
        self.assertEqual(e2e.hpke_open(sk, HEX(h["enc"]), HEX(h["info"]), HEX(first["aad"]), HEX(first["ct"])).hex(), first["pt"])
        ct = HEX(first["ct"])
        with self.assertRaises(ValueError):
            e2e.open_at(sk, HEX(h["enc"]), HEX(h["info"]), HEX(first["aad"]), bytes([ct[0] ^ 1]) + ct[1:], HEX(first["nonce"]))
        enc = HEX(h["enc"])
        with self.assertRaises(ValueError):
            e2e.hpke_open(sk, enc[:-1] + bytes([enc[-1] ^ 1]), HEX(h["info"]), HEX(first["aad"]), ct)

    def test_reproduces_the_vector_identities_day_key_and_signatures_and_opens_the_envelope(self):
        v = VECTORS
        for who in (v["alice_identity"], v["bob_identity"]):
            self.assertEqual(e2e.b64(e2e.identity_public_of(U(who["private"]))), who["public"])
            self.assertEqual(e2e.fingerprint(U(who["public"])), who["fingerprint"])
        day = v["bob_day_key"]
        published = {k: day[k] for k in ("key_id", "public_key", "valid_from", "expires_at", "signature")}
        self.assertEqual(e2e.b64(e2e.message_public_of(U(day["private_seed"]))), day["public_key"])
        self.assertEqual(e2e.key_id(U(day["public_key"])), day["key_id"])
        statement = e2e.message_key_statement(day["public_key"], day["valid_from"], day["expires_at"])
        self.assertEqual(statement, day["statement"])
        self.assertEqual(e2e.sign_with(U(v["bob_identity"]["private"]), statement), day["signature"])
        # Any moment of the day gives the same day key.
        seed, made = e2e.message_key_for(U(v["bob_identity"]["private"]), U(day["private_seed"]), e2e.parse_time("2026-12-01T18:00:00Z"))
        self.assertEqual(json.dumps(made), json.dumps(published))
        bob = v["bob_identity"]
        self.assertTrue(e2e.check_keys({"identity_key": bob["public"], "fingerprint": bob["fingerprint"], "message_key": published}))

        envelope = v["envelope"]
        self.assertTrue(e2e.is_envelope(envelope))
        self.assertEqual(e2e.envelope_statement(envelope), v["envelope_statement"])
        self.assertEqual(e2e.associated_data(envelope["sender_key"], envelope["recipient_key"]).decode(), v["associated_data"])
        self.assertTrue(e2e.verify_with(U(v["alice_identity"]["public"]), v["envelope_statement"], envelope["sig"]))
        payload = json.loads(v["plaintext_payload"])
        opened = e2e.open_message(envelope, U(day["private_seed"]), U(v["alice_identity"]["public"]), payload["to"], payload["from"])
        self.assertEqual(json.dumps(opened, ensure_ascii=False, separators=(",", ":")), v["plaintext_payload"])
        self.assertTrue(e2e.reveal_matches(opened["franking_key"], opened["text"], envelope["commitment"]))

        # Sealing the same payload again takes fresh randomness: a new seal, the same commitment.
        again = e2e.seal_message(
            payload["text"],
            payload["from"],
            payload["to"],
            U(v["alice_identity"]["private"]),
            U(v["alice_identity"]["public"]),
            published,
            now=e2e.parse_time(v["sent_at"]),
            franking_key=U(v["franking_key"]),
        )
        self.assertEqual(list(again), list(envelope))
        self.assertEqual(again["commitment"], envelope["commitment"])
        self.assertNotEqual(again["enc"], envelope["enc"])
        reopened = e2e.open_message(again, U(day["private_seed"]), U(v["alice_identity"]["public"]), payload["to"], payload["from"])
        self.assertEqual(json.dumps(reopened, ensure_ascii=False, separators=(",", ":")), v["plaintext_payload"])

    def test_makes_a_key_for_each_utc_day_signed_with_both_of_its_dates(self):
        bob_private, bob_public = e2e.generate_identity()
        keys = e2e.new_message_keys(bob_private, e2e.parse_time("2026-12-03T10:00:00Z"))
        self.assertEqual(len(keys), e2e.DAYS_AHEAD)
        self.assertEqual(
            [(k["valid_from"], k["expires_at"]) for _, k in keys],
            [(f"2026-12-{3 + i:02d}T00:00:00.000Z", f"2026-12-{4 + i:02d}T00:00:00.000Z") for i in range(7)],
        )
        for seed, k in keys:
            self.assertEqual(len(seed), e2e.SEED_BYTES)
            self.assertEqual(len(U(k["public_key"])), e2e.PUBLIC_BYTES)
            self.assertTrue(e2e.check_message_key(bob_public, k))
        self.assertEqual(len({k["key_id"] for _, k in keys}), 7)
        self.assertEqual(e2e.iso(e2e.day_start(e2e.parse_time("2026-12-03T23:59:59.999Z"))), "2026-12-03T00:00:00.000Z")
        today = keys[0][1]
        self.assertFalse(e2e.check_message_key(bob_public, {**today, "valid_from": "2026-12-03T12:00:00.000Z"}), "not a whole day")
        self.assertFalse(e2e.check_message_key(bob_public, {**today, "expires_at": keys[1][1]["expires_at"]}))
        self.assertFalse(e2e.check_message_key(e2e.generate_identity()[1], today), "someone else's signature")
        self.assertFalse(e2e.check_message_key(bob_public, {**today, "key_id": "0" * 32}))

    def test_opens_for_its_recipient_only_and_refuses_every_kind_of_tampering(self):
        alice_private, alice_public = e2e.generate_identity()
        bob_private, bob_public = e2e.generate_identity()
        (bob_key_private, bob_key), (tomorrow_private, _) = e2e.new_message_keys(bob_private)[:2]
        text = "Can you check the build log? Ünïcödé ✓"
        envelope = e2e.seal_message(text, "alice-id", "bob-id", alice_private, alice_public, bob_key)
        self.assertTrue(e2e.is_envelope(envelope))
        self.assertEqual(len(U(envelope["enc"])), e2e.ENC_BYTES)

        def read(e=envelope, me="bob-id", sender="alice-id", key=alice_public, private=bob_key_private):
            return e2e.open_message(e, private, key, me, sender)

        payload = read()
        self.assertEqual(payload["text"], text)
        self.assertFalse(e2e.reveal_matches(payload["franking_key"], "Something else", envelope["commitment"]))

        def flip(s):
            raw = U(s)
            return e2e.b64(bytes([raw[0] ^ 1]) + raw[1:])

        def resign(e):
            unsigned = {k: e[k] for k in ("suite", "sender_key", "recipient_key", "enc", "ct", "commitment")}
            return {**e, "sig": e2e.sign_with(alice_private, e2e.envelope_statement(unsigned))}

        with self.assertRaisesRegex(ValueError, "signature"):
            read({**envelope, "ct": flip(envelope["ct"])})
        with self.assertRaises(ValueError):
            read(resign({**envelope, "ct": flip(envelope["ct"])}))
        with self.assertRaises(ValueError):
            read(resign({**envelope, "enc": flip(envelope["enc"])}))
        with self.assertRaisesRegex(ValueError, "signature"):
            read({**envelope, "commitment": flip(envelope["commitment"])})
        with self.assertRaisesRegex(ValueError, "other agents"):
            read(me="carol-id")
        with self.assertRaisesRegex(ValueError, "other agents"):
            read(sender="mallory-id")
        with self.assertRaisesRegex(ValueError, "sender's key"):
            read(key=bob_public)
        with self.assertRaises(ValueError, msg="another day's key can't open it"):
            read(private=tomorrow_private)
        _, mallory = e2e.generate_identity()
        resigned = {**envelope, "sender_key": e2e.fingerprint(mallory), "sig": e2e.b64(bytes(64))}
        with self.assertRaisesRegex(ValueError, "signature"):
            read(resigned, key=mallory)
        self.assertFalse(e2e.is_envelope({**envelope, "extra": 1}))
        self.assertFalse(e2e.is_envelope({**envelope, "v": 1}))
        self.assertFalse(e2e.is_envelope({**envelope, "v": True}))
        self.assertFalse(e2e.is_envelope({**envelope, "suite": "x25519-hkdf-sha256-aes128gcm"}))
        self.assertFalse(e2e.is_envelope({**envelope, "enc": e2e.b64(bytes(32))}))
        self.assertFalse(e2e.is_envelope({**envelope, "sig": e2e.b64(bytes(32))}))
        seal = lambda t: e2e.seal_message(t, "a", "b", alice_private, alice_public, bob_key)
        # 2,000 characters fit in any script; 2,001 don't.
        self.assertLessEqual(len(json.dumps(seal("😀" * 2000), separators=(",", ":"))), e2e.MAX_ENVELOPE_BYTES)
        self.assertLessEqual(len(json.dumps(seal("界" * 2000), separators=(",", ":"))), e2e.MAX_ENVELOPE_BYTES)
        with self.assertRaises(ValueError):
            seal("a" * 2001)

    def test_exports_keys_with_a_passphrase_and_only_that_passphrase_imports_them(self):
        entry = {"identity": {"private": "p", "public": "q"}, "message_keys": [], "pins": {}}
        sealed = e2e.export_keys(entry, "correct horse battery staple")
        self.assertEqual(list(sealed), ["v", "kdf", "n", "r", "p", "salt", "nonce", "ct"])
        self.assertEqual([sealed[k] for k in ("v", "kdf", "n", "r", "p")], [1, "scrypt", 32768, 8, 1])
        self.assertEqual((len(U(sealed["salt"])), len(U(sealed["nonce"]))), (16, 12))
        self.assertEqual(e2e.import_keys(sealed, "correct horse battery staple"), entry)
        with self.assertRaisesRegex(ValueError, "Wrong passphrase"):
            e2e.import_keys(sealed, "wrong")


NODE_SEAL = """
import * as e from %s;
const alice = e.generateIdentity();
const bob = e.generateIdentity();
const [key] = e.newMessageKeys(bob.privateKey);
const text = "Sealed in JavaScript: Ünïcödé ✓ 😀";
const envelope = e.sealMessage({ text, from: "alice-id", to: "bob-id", identityPrivate: alice.privateKey,
  identityPublic: alice.publicKey, recipientKey: key.public });
const entry = { identity: { private: e.b64(alice.privateKey), public: e.b64(alice.publicKey) }, message_keys: [], pins: {} };
console.log(JSON.stringify({ text, alice_public: e.b64(alice.publicKey), bob_public: e.b64(bob.publicKey),
  bob_key: { private: e.b64(key.privateKey), ...key.public }, envelope, entry, exported: e.exportKeys(entry, "pass phrase") }));
"""

NODE_OPEN = """
import * as e from %s;
import { readFileSync } from "node:fs";
const made = JSON.parse(readFileSync(0, "utf8"));
const keys = { identity_key: made.bob_public, fingerprint: e.fingerprint(e.unb64(made.bob_public)), message_key: made.bob_key };
const payload = e.openMessage({ envelope: made.envelope, messagePrivate: e.unb64(made.bob_private), senderIdentityPublic: e.unb64(made.alice_public),
  me: "bob-id", sender: "alice-id" });
console.log(JSON.stringify({ checks: e.checkKeys(keys), envelope: e.isEnvelope(made.envelope), payload,
  commitment: e.revealMatches(payload.franking_key, payload.text, made.envelope.commitment), imported: e.importKeys(made.exported, "pass phrase") }));
"""


@unittest.skipUnless(HAS_NODE, "needs Node 24.7 or later to run the JavaScript SDK")
class CrossLanguageTest(unittest.TestCase):
    def node(self, script: str, stdin: str = "") -> dict:
        source = script % json.dumps((ROOT / "js" / "e2e.js").as_uri())
        done = subprocess.run(["node", "--input-type=module", "-e", source], input=stdin, check=True, capture_output=True, text=True)
        return json.loads(done.stdout)

    def test_opens_an_envelope_and_an_export_the_javascript_sdk_made(self):
        made = self.node(NODE_SEAL)
        bob_key = made["bob_key"]
        self.assertTrue(
            e2e.check_keys({"identity_key": made["bob_public"], "fingerprint": e2e.fingerprint(U(made["bob_public"])), "message_key": bob_key})
        )
        self.assertEqual(e2e.message_public_of(U(bob_key["private"])), U(bob_key["public_key"]))
        payload = e2e.open_message(made["envelope"], U(bob_key["private"]), U(made["alice_public"]), "bob-id", "alice-id")
        self.assertEqual(payload["text"], made["text"])
        self.assertTrue(e2e.reveal_matches(payload["franking_key"], payload["text"], made["envelope"]["commitment"]))
        self.assertEqual(e2e.import_keys(made["exported"], "pass phrase"), made["entry"])

    def test_the_javascript_sdk_opens_an_envelope_and_an_export_python_made(self):
        alice_private, alice_public = e2e.generate_identity()
        bob_private, bob_public = e2e.generate_identity()
        bob_seed, bob_key = e2e.new_message_keys(bob_private)[0]
        text = "Sealed in Python: Ünïcödé ✓ 😀"
        envelope = e2e.seal_message(text, "alice-id", "bob-id", alice_private, alice_public, bob_key)
        entry = {"identity": {"private": e2e.b64(alice_private), "public": e2e.b64(alice_public)}, "message_keys": [], "pins": {}}
        made = {
            "alice_public": e2e.b64(alice_public),
            "bob_public": e2e.b64(bob_public),
            "bob_key": bob_key,
            "bob_private": e2e.b64(bob_seed),
            "envelope": envelope,
            "exported": e2e.export_keys(entry, "pass phrase"),
        }
        opened = self.node(NODE_OPEN, json.dumps(made))
        self.assertEqual((opened["checks"], opened["envelope"], opened["commitment"]), (True, True, True))
        self.assertEqual(opened["payload"]["text"], text)
        self.assertEqual((opened["payload"]["from"], opened["payload"]["to"]), ("alice-id", "bob-id"))
        self.assertEqual(opened["imported"], entry)


class FakeServer:
    """A stand-in for the aMessage API's chat and key calls, for several agents at once. It checks
    envelopes as the server does (shape, the sender's signature, the recipient's key) and never opens one."""

    def __init__(self):
        self.tokens, self.keys, self.phones = {}, {}, {}
        self.conversations, self.messages, self.reports, self.calls, self.refuse_next = {}, {}, [], [], []
        # Agents whose day keys ran out: no key for today to seal to, but an identity still.
        self.lapsed = set()

    @staticmethod
    def problem(status, code):
        return status, {}, json.dumps({"code": code, "detail": f"Refused: {code}."})

    def published(self, agent_id):
        """Today's key, as GET /v1/agents/{id}/keys answers."""
        k = None if agent_id in self.lapsed else self.keys.get(agent_id)
        if not k:
            return None
        now = datetime.now(timezone.utc)
        today = [m for m in k["message_keys"] if e2e.parse_time(m["valid_from"]) <= now < e2e.parse_time(m["expires_at"])]
        if not today:
            return None
        key = max(today, key=lambda m: m["valid_from"])
        return {"agent_id": agent_id, "identity_key": k["identity_key"], "fingerprint": k["fingerprint"], "message_key": key}

    def keys_until(self, agent_id):
        return max(m["expires_at"] for m in self.keys[agent_id]["message_keys"])

    def chat_between(self, a, b):
        for c in self.conversations.values():
            if a in c["agents"] and b in c["agents"]:
                return c
        c = {"id": str(uuid4()), "agents": [a, b], "encrypted": False}
        self.conversations[c["id"]] = c
        return c

    def ok(self, value, status=200):
        return status, {}, json.dumps(value)

    def __call__(self, method, url, headers, body):
        path = urlparse(url).path
        body = json.loads(body) if body else None
        self.calls.append((method, path, headers, body))
        if path == "/v1/agents" and method == "POST":
            agent = str(uuid4())
            self.tokens[f"agt_{agent}"] = agent
            return self.ok({"agent": {"agent_id": agent, "inbox_id": agent, "linked_to_account": False}, "token": f"agt_{agent}"}, 201)
        me = self.tokens.get(headers.get("Authorization", "").replace("Bearer ", ""))
        if not me:
            return self.problem(401, "connect_first")
        if path == "/v1/me":
            encryption = {"fingerprint": self.keys[me]["fingerprint"]} if me in self.keys else None
            return self.ok({"agent_id": me, "inbox_id": me, "name": None, "linked_to_account": False, "encryption": encryption})
        if path == "/v1/me/keys" and method == "PUT":
            identity = e2e.unb64(body["identity_key"])
            fp = e2e.fingerprint(identity)
            days = body.get("message_keys")
            if len(identity) != 32 or not isinstance(days, list) or not 1 <= len(days) <= 14:
                return self.problem(400, "bad_request")
            now = datetime.now(timezone.utc)
            if not all(e2e.check_message_key(identity, m) and e2e.parse_time(m["expires_at"]) > now for m in days):
                return self.problem(400, "bad_request")
            before = self.keys.get(me)
            # A new identity key replaces the old one, and the old one's day keys stop taking messages.
            if not before or before["identity_key"] != body["identity_key"]:
                self.keys[me] = {"identity_key": body["identity_key"], "fingerprint": fp, "message_keys": []}
            held = self.keys[me]["message_keys"]
            for m in days:
                if all(k["key_id"] != m["key_id"] for k in held):
                    held.append(m)
            self.lapsed.discard(me)
            return self.ok(self.published(me)) if self.published(me) else self.problem(400, "bad_request")
        if path == "/v1/me/keys":
            if not self.published(me):
                return self.problem(404, "not_found")
            return self.ok({**self.published(me), "keys_until": self.keys_until(me)})
        parts = path.strip("/").split("/")
        if len(parts) == 4 and parts[1] == "agents" and parts[3] == "keys":
            answer = self.published(parts[2])
            return self.ok(answer) if answer else self.problem(404, "not_found")
        if path == "/v1/key-lookups":
            answer = self.published(self.phones.get(body["to"].get("phone") or body["to"].get("email")))
            return self.ok(answer) if answer else self.problem(404, "not_found")
        if parts[1] == "conversations" and len(parts) >= 3:
            c = self.conversations.get(parts[2])
            if not c or me not in c["agents"]:
                return self.problem(404, "not_found")
            if len(parts) == 3:
                other = next(a for a in c["agents"] if a != me)
                return self.ok({"id": c["id"], "counterpart": {"agent_id": other}, "encrypted": c["encrypted"]})
            if parts[3] == "messages":
                data = [m for m in self.messages.values() if m["conversation_id"] == c["id"]][::-1]
                return self.ok({"data": data, "next_cursor": None})
            for shown in body.get("reveal") or []:
                m = self.messages.get(shown["message_id"])
                if not m or not m["encrypted"] or not e2e.reveal_matches(shown["franking_key"], shown["text"], m["encrypted"]["commitment"]):
                    return self.problem(422, "reveal_mismatch")
            self.reports.append(body)
            return self.ok({"id": str(uuid4()), "blocked": body["block"]}, 201)
        if parts[1] == "messages" and len(parts) == 3:
            return self.ok(self.messages[parts[2]]) if parts[2] in self.messages else self.problem(404, "not_found")
        if path == "/v1/messages" and method == "POST":
            if self.refuse_next:
                return self.problem(409, self.refuse_next.pop(0))
            to = body["to"]
            other = to.get("agent_id") or self.phones.get(to.get("phone"))
            if not other and to.get("conversation_id") in self.conversations:
                other = next(a for a in self.conversations[to["conversation_id"]]["agents"] if a != me)
            if not other:
                return self.problem(404, "not_found")
            c = self.chat_between(me, other)
            env = body.get("encrypted")
            if env is not None:
                sender, recipient = self.keys.get(me), self.keys.get(other) or {}
                if not e2e.is_envelope(env) or "text" in body:
                    return self.problem(422, "invalid_envelope")
                if not sender or env["sender_key"] != sender["fingerprint"]:
                    return self.problem(409, "stale_key")
                if not e2e.verify_with(e2e.unb64(sender["identity_key"]), e2e.envelope_statement(env), env["sig"]):
                    return self.problem(422, "invalid_envelope")
                now = datetime.now(timezone.utc)
                usable = [
                    k["key_id"]
                    for k in recipient.get("message_keys", [])
                    if e2e.parse_time(k["expires_at"]) + e2e.DAY > now and e2e.parse_time(k["valid_from"]) <= now + e2e.DAY
                ]
                if env["recipient_key"] not in usable:
                    return self.problem(409, "stale_key")
                c["encrypted"] = True
            elif c["encrypted"]:
                return self.problem(409, "encrypted_chat")
            m = {
                "id": str(uuid4()),
                "state": "posted",
                "request_id": None,
                "conversation_id": c["id"],
                "sender_agent_id": me,
                "authored_by": "agent",
                "text": None if env else body["text"],
                "encrypted": env,
                "reply_to_message_id": body.get("reply_to_message_id"),
                "created_at": e2e.iso(datetime.now(timezone.utc)),
                "posted_at": e2e.iso(datetime.now(timezone.utc)),
                "beacon_id": None,
            }
            self.messages[m["id"]] = m
            return self.ok(m, 201)
        return self.problem(404, "not_found")

    def sends(self):
        return [c for c in self.calls if c[0] == "POST" and c[1] == "/v1/messages"]

    def puts(self):
        return [c for c in self.calls if c[0] == "PUT" and c[1] == "/v1/me/keys"]


class Agent:
    def __init__(self, server, **options):
        self.home = Path(tempfile.mkdtemp(prefix="amessage-e2e-"))
        self.op = AMessage(send=server, env={}, home=self.home, **options)
        self.op.connect()
        self.dir = self.home / ".config" / "amessage"
        self.id = json.loads((self.dir / "credentials.json").read_text())[API]["agent_id"]

    def file(self, name):
        return json.loads((self.dir / name).read_text())

    def mode(self, name):
        return stat.S_IMODE(os.stat(self.dir / name).st_mode)

    def entry(self):
        return self.file("keys.json")[API][self.id]


class EncryptedChatTest(unittest.TestCase):
    def test_keeps_keys_beside_the_credentials_seals_by_itself_and_opens_what_it_reads(self):
        server = FakeServer()
        alice, bob = Agent(server, encryption=True), Agent(server, encryption=True)
        published = bob.op.create_keys()
        self.assertEqual(published["agent_id"], bob.id)
        self.assertEqual(bob.mode("keys.json"), 0o600)
        entry = bob.entry()
        self.assertEqual(list(entry), ["identity", "message_keys", "pins"])
        self.assertEqual(list(entry["identity"]), ["private", "public"])
        self.assertEqual(len(entry["message_keys"]), 7, "a key for each of the next 7 days")
        self.assertEqual(list(entry["message_keys"][0]), ["key_id", "private", "public_key", "valid_from", "expires_at", "signature"])
        today = e2e.day_start(datetime.now(timezone.utc))
        self.assertEqual([k["valid_from"] for k in entry["message_keys"]], [e2e.iso(today + i * e2e.DAY) for i in range(7)])
        for k in entry["message_keys"]:
            self.assertEqual(len(e2e.unb64(k["private"])), e2e.SEED_BYTES)
        put = server.puts()[-1][3]
        self.assertEqual(list(put), ["identity_key", "message_keys"])
        self.assertEqual(
            put["message_keys"],
            [{f: k[f] for f in ("key_id", "public_key", "valid_from", "expires_at", "signature")} for k in entry["message_keys"]],
            "the public halves of all 7 days, in order",
        )
        self.assertEqual(published["fingerprint"], e2e.fingerprint(e2e.unb64(entry["identity"]["public"])))
        self.assertEqual(published["message_key"]["key_id"], entry["message_keys"][0]["key_id"], "today's key")
        self.assertEqual(bob.op.keys(), {**published, "keys_until": entry["message_keys"][6]["expires_at"]})
        self.assertEqual(bob.op.create_keys()["fingerprint"], published["fingerprint"], "a second call keeps the identity")
        self.assertEqual(
            [k["key_id"] for k in bob.entry()["message_keys"]],
            [k["key_id"] for k in entry["message_keys"]],
            "and makes no new keys for days it has",
        )

        sent = alice.op.send_message({"agent_id": bob.id}, "Can you check the build log?")
        self.assertIsNone(sent["text"])
        self.assertTrue(e2e.is_envelope(sent["encrypted"]))
        self.assertEqual(sent["opened"], {"text": "Can you check the build log?", "verified": True})
        post = server.sends()[-1]
        self.assertNotIn("text", post[3])
        self.assertEqual(post[3]["to"], {"agent_id": bob.id})
        self.assertIn(alice.id, server.keys, "encryption=True made and published Alice's keys first")
        self.assertEqual(alice.entry()["pins"], {bob.id: published["fingerprint"]})
        self.assertEqual(alice.mode("sent.json"), 0o600)
        self.assertEqual(list(alice.file("sent.json")[API][alice.id][sent["id"]]), ["text", "sent_at"])

        page = bob.op.read_conversation(sent["conversation_id"])
        self.assertIsNone(page["data"][0]["text"])
        self.assertEqual(page["data"][0]["encrypted"], sent["encrypted"])
        self.assertEqual(page["data"][0]["opened"], {"text": "Can you check the build log?", "verified": True})
        self.assertEqual(bob.op.chat({"action": "read", "id": sent["id"]})["opened"], page["data"][0]["opened"])

        reply = bob.op.reply(sent["conversation_id"], "Yes, on it.", sent["id"])
        self.assertIsNotNone(reply["encrypted"], "a reply in the conversation is sealed to its other agent")
        history = alice.op.chat({"action": "messages", "id": sent["conversation_id"]})
        self.assertEqual(
            [m["opened"] for m in history["data"]],
            [{"text": "Yes, on it.", "verified": True}, {"text": "Can you check the build log?", "verified": True}],
        )
        elsewhere = AMessage(send=server, env={}, home=Path(tempfile.mkdtemp()), token=f"agt_{alice.id}")
        there = elsewhere.read_conversation(sent["conversation_id"])
        self.assertEqual(there["data"][1]["opened"], {"text": None, "verified": False, "reason": "sent from another machine"})
        self.assertIsNone(there["data"][0]["opened"]["text"], "no keys on that machine")

        wire = json.dumps([c[3] for c in server.calls])
        for who in (alice, bob):
            e = who.entry()
            for secret in [e["identity"]["private"], *(k["private"] for k in e["message_keys"])]:
                self.assertNotIn(secret, wire)

    def test_wont_publish_over_keys_another_machine_holds_even_when_their_day_keys_ran_out(self):
        server = FakeServer()
        first, bob = Agent(server, encryption=True), Agent(server, encryption=True)
        first.op.create_keys()
        bob.op.create_keys()
        original = server.keys[first.id]["fingerprint"]
        server.lapsed.add(first.id)
        second = AMessage(send=server, env={}, home=Path(tempfile.mkdtemp()), token=f"agt_{first.id}", encryption=True)
        self.assertIsNone(second.keys(), "GET /v1/me/keys says nothing without a key for today")
        before = len(server.puts())
        with self.assertRaises(EncryptionError) as caught:
            second.create_keys()
        self.assertEqual((caught.exception.code, caught.exception.fingerprint), ("keys_elsewhere", original))
        self.assertIn("on another machine", str(caught.exception))
        self.assertIn("replace=True", str(caught.exception))
        for attempt in (
            lambda: second.send_message({"agent_id": bob.id}, "Hi"),
            lambda: second.chat({"action": "publish_keys"}),
        ):
            with self.assertRaises(EncryptionError) as refused:
                attempt()
            self.assertEqual(refused.exception.code, "keys_elsewhere")
        self.assertEqual(len(server.puts()), before, "nothing was published")
        self.assertEqual(server.keys[first.id]["fingerprint"], original)
        self.assertEqual(first.op.create_keys()["fingerprint"], original, "the machine that holds them publishes as before")
        replaced = second.create_keys(replace=True)
        self.assertNotEqual(replaced["fingerprint"], original)
        for attempt in (first.op.create_keys, lambda: first.op.chat({"action": "publish_keys"})):
            with self.assertRaises(EncryptionError) as refused:
                attempt()
            self.assertEqual(refused.exception.code, "keys_elsewhere")
        self.assertEqual(server.keys[first.id]["fingerprint"], replaced["fingerprint"])

    def test_sends_plain_when_it_should_and_refuses_plain_only_where_it_must(self):
        server = FakeServer()
        alice, bob, carol = Agent(server, encryption=True), Agent(server), Agent(server)
        bob.op.create_keys()
        plain = alice.op.send_message({"agent_id": carol.id}, "Hello Carol")
        self.assertEqual(plain["text"], "Hello Carol")
        self.assertNotIn("opened", plain)
        with self.assertRaises(EncryptionError) as caught:
            alice.op.send_message({"agent_id": carol.id}, "Hi", encrypted=True)
        self.assertEqual(caught.exception.code, "no_keys")
        alice.op.send_message({"agent_id": bob.id}, "Sealed")
        with self.assertRaises(AMessageError) as refused:
            alice.op.send_message({"agent_id": bob.id}, "Not sealed", plain=True)
        self.assertEqual(refused.exception.code, "encrypted_chat")
        quiet = Agent(server)
        quiet.op.send_message({"agent_id": carol.id}, "Plain")
        self.assertEqual(server.sends()[-1][3]["text"], "Plain")
        self.assertIsNotNone(quiet.op.chat({"action": "send", "to": {"agent_id": bob.id}, "text": "Sealed anyway", "encrypted": True})["encrypted"])
        with self.assertRaises(AMessageError):
            alice.op.message(str(uuid4()), "Hi")
        self.assertEqual(server.sends()[-1][3]["text"], "Hi", "a beacon's owner can't be known, so it gets plain words")

    def test_stops_sealing_after_a_key_change_until_trust_key(self):
        server = FakeServer()
        alice, bob = Agent(server, encryption=True), Agent(server, encryption=True)
        bob.op.create_keys()
        first = alice.op.send_message({"agent_id": bob.id}, "Before the change")
        old = alice.op.agent_keys(bob.id)["fingerprint"]
        renewed = bob.op.create_keys(replace=True)
        self.assertNotEqual(renewed["fingerprint"], old)
        self.assertEqual(bob.op.read_conversation(first["conversation_id"])["data"][0]["opened"]["text"], "Before the change")
        with self.assertRaises(EncryptionError) as caught:
            alice.op.send_message({"agent_id": bob.id}, "After")
        error = caught.exception
        self.assertEqual((error.code, error.pinned, error.fingerprint), ("key_changed", old, renewed["fingerprint"]))
        self.assertIn("trust_key", str(error))
        posts = len(server.sends())
        with self.assertRaises(EncryptionError):
            alice.op.seal({"agent_id": bob.id}, "After")
        self.assertEqual(len(server.sends()), posts, "nothing was sent")
        self.assertTrue(alice.op.agent_keys(bob.id)["key_changed"])
        bob.op.send_message({"agent_id": alice.id}, "New key, same Bob")
        page = alice.op.read_conversation(first["conversation_id"])
        self.assertEqual(
            page["data"][0]["opened"], {"text": "New key, same Bob", "verified": False, "reason": "their key changed since your first chat"}
        )
        with self.assertRaises(EncryptionError) as mismatch:
            alice.op.trust_key(bob.id, old)
        self.assertEqual(mismatch.exception.code, "fingerprint_mismatch")
        self.assertFalse(alice.op.trust_key(bob.id, renewed["fingerprint"])["key_changed"])
        self.assertIsNotNone(alice.op.send_message({"agent_id": bob.id}, "After")["encrypted"])
        self.assertTrue(alice.op.read_conversation(first["conversation_id"])["data"][1]["opened"]["verified"])

    def test_publishes_the_next_days_when_fewer_than_3_are_left_keeps_180_days_and_drops_version_1_keys(self):
        server = FakeServer()
        alice, bob = Agent(server, encryption=True), Agent(server, encryption=True)
        bob.op.create_keys()
        early = alice.op.send_message({"agent_id": bob.id}, "Sealed to today's key")
        everything = bob.file("keys.json")
        keys = everything[API][bob.id]["message_keys"]
        today = keys[0]
        # Three days left: nothing to publish yet.
        everything[API][bob.id]["message_keys"] = keys[:4]
        (bob.dir / "keys.json").write_text(json.dumps(everything))
        before = len(server.puts())
        bob.op.read_conversation(early["conversation_id"])
        self.assertEqual(len(server.puts()), before, "three days left is enough")
        # Two days left, an ancient key and a key of version 1: reading publishes, and tidies.
        now = datetime.now(timezone.utc)
        ancient = {**today, "key_id": "0" * 32, "valid_from": e2e.iso(now - timedelta(days=182)), "expires_at": e2e.iso(now - timedelta(days=181))}
        kept = {**today, "key_id": "1" * 32, "valid_from": e2e.iso(now - timedelta(days=171)), "expires_at": e2e.iso(now - timedelta(days=170))}
        version1 = {"key_id": "2" * 32, "private": today["private"], "public_key": "abc", "expires_at": e2e.iso(now + e2e.DAY), "signature": "abc"}
        everything[API][bob.id]["message_keys"] = [version1, ancient, kept, *keys[:2]]
        everything[API][bob.id]["pins"] = {alice.id: "a" * 64}
        (bob.dir / "keys.json").write_text(json.dumps(everything))
        before = len(server.puts())
        page = bob.op.read_conversation(early["conversation_id"])
        self.assertEqual(
            page["data"][0]["opened"],
            {"text": "Sealed to today's key", "verified": False, "reason": "their key changed since your first chat"},
            "pins stayed",
        )
        self.assertEqual(len(server.puts()), before + 1, "reading published the next days")
        published = server.puts()[-1][3]["message_keys"]
        self.assertEqual(len(published), 7)
        self.assertEqual([k["key_id"] for k in published[:2]], [k["key_id"] for k in keys[:2]], "the days it had, again")
        after = bob.entry()
        self.assertEqual(list(after), ["identity", "message_keys", "pins"])
        self.assertEqual(
            [k["key_id"] for k in after["message_keys"]],
            [kept["key_id"], *(k["key_id"] for k in published)],
            "version 1 and 181-day-old keys are gone; one 170 days old stays",
        )
        self.assertEqual(bob.mode("keys.json"), 0o600)
        # Sealed to a later day's key, it opens with that key.
        identity = alice.entry()["identity"]
        later = e2e.seal_message(
            "Sealed to tomorrow's key", alice.id, bob.id, e2e.unb64(identity["private"]), e2e.unb64(identity["public"]), after["message_keys"][2]
        )
        bob.op.trust_key(alice.id)
        self.assertEqual(
            bob.op.open({"id": str(uuid4()), "encrypted": later, "sender_agent_id": alice.id}),
            {"text": "Sealed to tomorrow's key", "verified": True},
        )

    def test_drops_a_replayed_envelope_but_reads_the_same_message_again_as_often_as_asked(self):
        server = FakeServer()
        alice, bob = Agent(server, encryption=True), Agent(server, encryption=True)
        bob.op.create_keys()
        sent = alice.op.send_message({"agent_id": bob.id}, "Pay invoice 42")
        first = bob.op.read_conversation(sent["conversation_id"])
        again = bob.op.read_conversation(sent["conversation_id"])
        self.assertEqual(first["data"][0]["opened"], {"text": "Pay invoice 42", "verified": True})
        self.assertEqual(again["data"][0]["opened"], first["data"][0]["opened"], "a second read is no replay")
        self.assertEqual(bob.op.chat({"action": "read", "id": sent["id"]})["opened"], first["data"][0]["opened"])
        self.assertEqual(bob.mode("seen.json"), 0o600)
        commitment = sent["encrypted"]["commitment"]
        seen = bob.file("seen.json")[API][bob.id]
        self.assertEqual(list(seen), [commitment])
        self.assertEqual(list(seen[commitment]), ["message_id", "opened_at"])
        self.assertEqual(seen[commitment]["message_id"], sent["id"])

        # Someone posts the same envelope again: it reads as a copy, and the original still reads.
        copy = {**server.messages[sent["id"]], "id": str(uuid4()), "posted_at": e2e.iso(datetime.now(timezone.utc) + timedelta(seconds=1))}
        server.messages[copy["id"]] = copy
        replay = {"text": None, "verified": False, "reason": "a copy of a message already opened"}
        page = bob.op.read_conversation(sent["conversation_id"])
        self.assertEqual(
            [(m["id"], m["opened"]) for m in page["data"]],
            [(copy["id"], replay), (sent["id"], {"text": "Pay invoice 42", "verified": True})],
        )
        self.assertIsNone(bob.op.chat({"action": "read", "id": copy["id"]})["opened"]["text"])
        self.assertEqual(bob.op.open(copy), replay)
        # A request carries its message's id, so it reads as that message.
        request = {"id": str(uuid4()), "message_id": sent["id"], "sender": {"agent_id": alice.id}, "encrypted": sent["encrypted"], "text": None}
        self.assertEqual(bob.op.open(request), {"text": "Pay invoice 42", "verified": True})
        # An incoming request still waiting has no message id yet: a fresh envelope reads, and is only
        # remembered once its message is read; one opened before is a replay.
        waiting = {"id": str(uuid4()), "direction": "incoming", "sender": {"agent_id": alice.id}, "text": None}
        fresh = alice.op.seal({"agent_id": bob.id}, "Lunch on Friday?")
        for _ in range(2):
            self.assertEqual(bob.op.open({**waiting, "encrypted": fresh}), {"text": "Lunch on Friday?", "verified": True})
        self.assertEqual(bob.op.open({**waiting, "encrypted": sent["encrypted"]}), replay)
        with self.assertRaises(EncryptionError) as caught:
            bob.op.report_conversation(sent["conversation_id"], "spam", reveal=[copy["id"]])
        self.assertEqual(caught.exception.code, "cant_open")
        self.assertEqual(list(bob.file("seen.json")[API][bob.id]), [commitment])

        # Seen for the first time in one page, the older of two copies is the one that reads.
        (bob.dir / "seen.json").write_text("{}")
        fresh = bob.op.read_conversation(sent["conversation_id"])
        self.assertEqual([m["opened"]["text"] for m in fresh["data"]], [None, "Pay invoice 42"])
        # Entries older than 180 days are dropped when it next writes.
        stale = e2e.iso(datetime.now(timezone.utc) - timedelta(days=181))
        (bob.dir / "seen.json").write_text(json.dumps({API: {bob.id: {"stale": {"message_id": "m", "opened_at": stale}}}}))
        bob.op.read_conversation(sent["conversation_id"])
        self.assertEqual(list(bob.file("seen.json")[API][bob.id]), [commitment])

    def test_finds_keys_by_phone_seals_without_sending_and_opens_one_message(self):
        server = FakeServer()
        alice, bob = Agent(server), Agent(server)
        phone = "+14155550100"
        server.phones[phone] = bob.id
        self.assertIsNone(alice.op.lookup_keys({"phone": phone}))
        bob.op.create_keys()
        alice.op.create_keys()
        found = alice.op.lookup_keys({"phone": phone})
        self.assertEqual((found["agent_id"], found["key_changed"]), (bob.id, False))
        self.assertEqual(server.calls[-1][1:4:2], ("/v1/key-lookups", {"to": {"phone": phone}}))
        envelope = alice.op.seal({"phone": phone}, "Sealed by hand")
        self.assertEqual(bob.op.open({"encrypted": envelope, "sender_agent_id": alice.id}), {"text": "Sealed by hand", "verified": True})
        self.assertEqual(
            bob.op.open({"encrypted": envelope, "sender_agent_id": str(uuid4())}),
            {"text": None, "verified": False, "reason": "the sender's keys couldn't be read"},
        )
        self.assertIsNone(bob.op.open({"text": "plain", "encrypted": None}))
        sent = alice.op.chat({"action": "send", "to": {"phone": phone}, "encrypted": envelope})
        self.assertEqual(server.sends()[-1][3], {"to": {"phone": phone}, "encrypted": envelope})
        self.assertEqual(sent["opened"], {"text": "Sealed by hand", "verified": True})
        self.assertEqual(alice.file("sent.json")[API][alice.id][sent["id"]]["text"], "Sealed by hand")
        request = {"id": str(uuid4()), "message_id": sent["id"], "sender": {"agent_id": alice.id}, "encrypted": envelope, "text": None}
        self.assertEqual(bob.op.open(request), {"text": "Sealed by hand", "verified": True})
        self.assertEqual(alice.op.open(request), {"text": "Sealed by hand", "verified": True}, "from sent.json")

    def test_on_stale_key_fetches_again_publishes_its_own_and_seals_once_more_with_the_same_key(self):
        server = FakeServer()
        alice, bob = Agent(server, encryption=True), Agent(server, encryption=True)
        bob.op.create_keys()
        server.refuse_next.append("stale_key")
        self.assertIsNotNone(alice.op.send_message({"agent_id": bob.id}, "Try twice", key="retry-key")["encrypted"])
        self.assertEqual([c[2]["Idempotency-Key"] for c in server.sends()], ["retry-key", "retry-key"])
        server.refuse_next.extend(["stale_key", "stale_key"])
        with self.assertRaises(AMessageError) as caught:
            alice.op.send_message({"agent_id": bob.id}, "Never")
        self.assertEqual(caught.exception.code, "stale_key")

    def test_chats_the_key_actions_as_calls_to_the_key_endpoints(self):
        server = FakeServer()
        alice, bob = Agent(server), Agent(server)
        self.assertIsNone(alice.op.chat({"action": "keys"}))
        self.assertIsNone(alice.op.chat({"action": "agent_keys", "agent_id": bob.id}))
        mine = alice.op.chat({"action": "publish_keys"})
        method, path, _, body = server.calls[-1]
        self.assertEqual((method, path), ("PUT", "/v1/me/keys"))
        self.assertEqual(list(body), ["identity_key", "message_keys"])
        self.assertEqual(len(body["message_keys"]), 7)
        self.assertEqual(list(body["message_keys"][0]), ["key_id", "public_key", "valid_from", "expires_at", "signature"])
        self.assertEqual(alice.op.chat({"action": "keys"}), {**mine, "keys_until": body["message_keys"][6]["expires_at"]})
        bob.op.create_keys()
        theirs = alice.op.chat({"action": "agent_keys", "agent_id": bob.id})
        self.assertEqual(server.calls[-1][1], f"/v1/agents/{bob.id}/keys")
        self.assertEqual(list(theirs), ["agent_id", "identity_key", "fingerprint", "message_key", "key_changed"])
        now = datetime.now(timezone.utc)
        self.assertTrue(e2e.parse_time(theirs["message_key"]["valid_from"]) <= now < e2e.parse_time(theirs["message_key"]["expires_at"]))
        server.phones["bob@example.com"] = bob.id
        self.assertEqual(alice.op.chat({"action": "key_lookup", "to": {"email": "bob@example.com"}})["agent_id"], bob.id)
        with self.assertRaises(ValueError):
            alice.op.chat({"action": "key_lookup"})
        server.keys[bob.id]["fingerprint"] = "f" * 64
        with self.assertRaises(EncryptionError) as caught:
            alice.op.agent_keys(bob.id)
        self.assertEqual(caught.exception.code, "bad_keys")

    def test_reports_with_reveal_open_the_messages_here_and_send_their_franking_keys(self):
        server = FakeServer()
        alice, bob = Agent(server, encryption=True), Agent(server, encryption=True)
        bob.op.create_keys()
        rude = alice.op.send_message({"agent_id": bob.id}, "Something abusive")
        bob.op.report_conversation(rude["conversation_id"], "abuse", reveal=[rude["id"]], key="report-key")
        [shown] = server.reports[0]["reveal"]
        self.assertEqual((shown["message_id"], shown["text"]), (rude["id"], "Something abusive"))
        self.assertTrue(e2e.reveal_matches(shown["franking_key"], shown["text"], rude["encrypted"]["commitment"]))
        self.assertEqual(server.calls[-1][2]["Idempotency-Key"], "report-key")
        with self.assertRaises(EncryptionError) as caught:
            alice.op.report_conversation(rude["conversation_id"], "spam", reveal=[rude["id"]])
        self.assertEqual(caught.exception.code, "cant_open")
        bob.op.report_conversation(rude["conversation_id"], "spam")
        self.assertEqual(server.reports[-1], {"reason": "spam", "block": True})


if __name__ == "__main__":
    unittest.main()
