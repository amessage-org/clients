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

# RFC 9180, Appendix A.1: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM, base mode.
A1 = {
    "info": bytes.fromhex("4f6465206f6e2061204772656369616e2055726e"),
    "ikmE": bytes.fromhex("7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234"),
    "pkEm": "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431",
    "skEm": "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736",
    "ikmR": bytes.fromhex("6db9df30aa07dd42ee5e8181afdb977e538f5e1fec8a06223f33f7013e525037"),
    "pkRm": "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d",
    "skRm": "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8",
    "sharedSecret": "fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc",
    "key": "4531685d41d65f03dc48f6b8302c05b0",
    "baseNonce": "56d890e5accaaf011cff4b7d",
    "pt": bytes.fromhex("4265617574792069732074727574682c20747275746820626561757479"),
    "aad": bytes.fromhex("436f756e742d30"),
    "ct": "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a",
}


class BuildingBlocksTest(unittest.TestCase):
    def test_matches_rfc_9180_a1(self):
        sk_e, pk_e = e2e.derive_x25519(A1["ikmE"])
        sk_r, pk_r = e2e.derive_x25519(A1["ikmR"])
        self.assertEqual((pk_e.hex(), sk_e.hex()), (A1["pkEm"], A1["skEm"]))
        self.assertEqual((pk_r.hex(), sk_r.hex()), (A1["pkRm"], A1["skRm"]))
        enc, ct = e2e.hpke_seal(pk_r, A1["info"], A1["aad"], A1["pt"], (sk_e, pk_e))
        self.assertEqual(enc.hex(), A1["pkEm"])
        schedule = e2e.inspect(enc, sk_r, A1["info"])
        self.assertEqual(schedule["shared"].hex(), A1["sharedSecret"])
        self.assertEqual(schedule["key"].hex(), A1["key"])
        self.assertEqual(schedule["nonce"].hex(), A1["baseNonce"])
        self.assertEqual(ct.hex(), A1["ct"])
        self.assertEqual(e2e.hpke_open(sk_r, enc, A1["info"], A1["aad"], ct), A1["pt"])
        with self.assertRaises(ValueError):
            e2e.hpke_open(sk_r, enc, A1["info"], A1["aad"], bytes([ct[0] ^ 1]) + ct[1:])

    def test_seals_the_spec_vectors_byte_for_byte_and_opens_them(self):
        v, u = VECTORS, e2e.unb64
        for who in (v["alice_identity"], v["bob_identity"]):
            self.assertEqual(e2e.b64(e2e.identity_public_of(u(who["private"]))), who["public"])
            self.assertEqual(e2e.fingerprint(u(who["public"])), who["fingerprint"])
        bob_key = v["bob_message_key"]
        self.assertEqual(e2e.b64(e2e.x25519_public_of(u(bob_key["private"]))), bob_key["public_key"])
        self.assertEqual(e2e.key_id(u(bob_key["public_key"])), bob_key["key_id"])
        statement = e2e.message_key_statement(bob_key["public_key"], bob_key["expires_at"])
        self.assertEqual(e2e.sign_with(u(v["bob_identity"]["private"]), statement), bob_key["signature"])
        bob = v["bob_identity"]
        self.assertTrue(e2e.check_keys({"identity_key": bob["public"], "fingerprint": bob["fingerprint"], "message_key": bob_key}))
        payload = json.loads(v["plaintext_payload"])
        ephemeral = u(v["ephemeral_private"])
        envelope = e2e.seal_message(
            payload["text"],
            payload["from"],
            payload["to"],
            u(v["alice_identity"]["private"]),
            u(v["alice_identity"]["public"]),
            bob_key,
            now=e2e.parse_time(v["sent_at"]),
            ephemeral=(ephemeral, e2e.x25519_public_of(ephemeral)),
            franking_key=u(v["franking_key"]),
        )
        self.assertEqual(json.dumps(envelope, separators=(",", ":")), json.dumps(v["envelope"], separators=(",", ":")))
        self.assertTrue(e2e.is_envelope(envelope))
        opened = e2e.open_message(v["envelope"], u(bob_key["private"]), u(v["alice_identity"]["public"]), payload["to"], payload["from"])
        self.assertEqual(json.dumps(opened, ensure_ascii=False, separators=(",", ":")), v["plaintext_payload"])
        self.assertTrue(e2e.reveal_matches(opened["franking_key"], opened["text"], v["envelope"]["commitment"]))

    def test_opens_for_its_recipient_only_and_refuses_every_kind_of_tampering(self):
        alice_private, alice_public = e2e.generate_identity()
        bob_private, bob_public = e2e.generate_identity()
        bob_key_private, bob_key = e2e.new_message_key(bob_private)
        text = "Can you check the build log? Ünïcödé ✓"
        envelope = e2e.seal_message(text, "alice-id", "bob-id", alice_private, alice_public, bob_key)

        def read(e=envelope, me="bob-id", sender="alice-id", key=alice_public):
            return e2e.open_message(e, bob_key_private, key, me, sender)

        payload = read()
        self.assertEqual(payload["text"], text)
        self.assertFalse(e2e.reveal_matches(payload["franking_key"], "Something else", envelope["commitment"]))

        def flip(s):
            raw = e2e.unb64(s)
            return e2e.b64(bytes([raw[0] ^ 1]) + raw[1:])

        with self.assertRaises(ValueError):
            read({**envelope, "ct": flip(envelope["ct"])})
        with self.assertRaisesRegex(ValueError, "signature"):
            read({**envelope, "commitment": flip(envelope["commitment"])})
        with self.assertRaisesRegex(ValueError, "other agents"):
            read(me="carol-id")
        with self.assertRaisesRegex(ValueError, "other agents"):
            read(sender="mallory-id")
        with self.assertRaisesRegex(ValueError, "sender's key"):
            read(key=bob_public)
        _, mallory = e2e.generate_identity()
        resigned = {**envelope, "sender_key": e2e.fingerprint(mallory), "sig": e2e.b64(bytes(64))}
        with self.assertRaisesRegex(ValueError, "signature"):
            read(resigned, key=mallory)
        self.assertFalse(e2e.is_envelope({**envelope, "extra": 1}))
        self.assertFalse(e2e.is_envelope({**envelope, "v": 2}))
        self.assertFalse(e2e.is_envelope({**envelope, "v": True}))
        seal = lambda t: e2e.seal_message(t, "a", "b", alice_private, alice_public, bob_key)
        # 2,000 characters fit in any script; 2,001 don't.
        self.assertLessEqual(len(json.dumps(seal("😀" * 2000), separators=(",", ":"))), e2e.MAX_ENVELOPE_BYTES)
        with self.assertRaises(ValueError):
            seal("a" * 2001)

    def test_exports_keys_with_a_passphrase_and_only_that_passphrase_imports_them(self):
        entry = {"identity": {"private": "p", "public": "q"}, "message_keys": [], "pins": {}}
        sealed = e2e.export_keys(entry, "correct horse battery staple")
        self.assertEqual(list(sealed), ["v", "kdf", "n", "r", "p", "salt", "nonce", "ct"])
        self.assertEqual([sealed[k] for k in ("v", "kdf", "n", "r", "p")], [1, "scrypt", 32768, 8, 1])
        self.assertEqual((len(e2e.unb64(sealed["salt"])), len(e2e.unb64(sealed["nonce"]))), (16, 12))
        self.assertEqual(e2e.import_keys(sealed, "correct horse battery staple"), entry)
        with self.assertRaisesRegex(ValueError, "Wrong passphrase"):
            e2e.import_keys(sealed, "wrong")


NODE_SEAL = """
import * as e from %s;
const alice = e.generateIdentity();
const bob = e.generateIdentity();
const key = e.newMessageKey(bob.privateKey);
const text = "Sealed in JavaScript: Ünïcödé ✓ 😀";
const envelope = e.sealMessage({ text, from: "alice-id", to: "bob-id", identityPrivate: alice.privateKey,
  identityPublic: alice.publicKey, recipientKey: key.public });
const entry = { identity: { private: e.b64(alice.privateKey), public: e.b64(alice.publicKey) }, message_keys: [], pins: {} };
console.log(JSON.stringify({ text, alice_public: e.b64(alice.publicKey), bob_public: e.b64(bob.publicKey),
  bob_key: { private: e.b64(key.privateKey), ...key.public }, envelope, entry, exported: e.exportKeys(entry, "pass phrase") }));
"""


@unittest.skipUnless(shutil.which("node"), "needs node to seal with the JavaScript SDK")
class CrossLanguageTest(unittest.TestCase):
    def test_opens_an_envelope_and_an_export_the_javascript_sdk_made(self):
        script = NODE_SEAL % json.dumps((ROOT / "js" / "e2e.js").as_uri())
        made = json.loads(subprocess.run(["node", "--input-type=module", "-e", script], check=True, capture_output=True, text=True).stdout)
        bob_key = made["bob_key"]
        self.assertTrue(
            e2e.check_keys({"identity_key": made["bob_public"], "fingerprint": e2e.fingerprint(e2e.unb64(made["bob_public"])), "message_key": bob_key})
        )
        payload = e2e.open_message(made["envelope"], e2e.unb64(bob_key["private"]), e2e.unb64(made["alice_public"]), "bob-id", "alice-id")
        self.assertEqual(payload["text"], made["text"])
        self.assertTrue(e2e.reveal_matches(payload["franking_key"], payload["text"], made["envelope"]["commitment"]))
        self.assertEqual(e2e.import_keys(made["exported"], "pass phrase"), made["entry"])


class FakeServer:
    """A stand-in for the aMessage API's chat and key calls, for several agents at once. It checks
    envelopes as the server does (shape, the sender's signature, the recipient's key) and never opens one."""

    def __init__(self):
        self.tokens, self.keys, self.phones = {}, {}, {}
        self.conversations, self.messages, self.reports, self.calls, self.refuse_next = {}, {}, [], [], []
        # Agents whose weekly message key lapsed: no keys to seal to, but an identity still.
        self.lapsed = set()

    @staticmethod
    def problem(status, code):
        return status, {}, json.dumps({"code": code, "detail": f"Refused: {code}."})

    def published(self, agent_id):
        k = None if agent_id in self.lapsed else self.keys.get(agent_id)
        if not k:
            return None
        return {"agent_id": agent_id, "identity_key": k["identity_key"], "fingerprint": k["fingerprint"], "message_key": k["message_keys"][-1]}

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
            fp = e2e.fingerprint(e2e.unb64(body["identity_key"]))
            if not e2e.check_keys({**body, "fingerprint": fp}):
                return self.problem(422, "invalid_keys")
            before = self.keys.get(me)
            if not before or before["identity_key"] != body["identity_key"]:
                self.keys[me] = {"identity_key": body["identity_key"], "fingerprint": fp, "message_keys": [body["message_key"]]}
            elif before["message_keys"][-1]["key_id"] != body["message_key"]["key_id"]:
                before["message_keys"].append(body["message_key"])
            self.lapsed.discard(me)
            return self.ok(self.published(me))
        if path == "/v1/me/keys":
            return self.ok(self.published(me)) if self.published(me) else self.problem(404, "not_found")
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
                usable = [k["key_id"] for k in recipient.get("message_keys", []) if e2e.parse_time(k["expires_at"]) + e2e.DAY > now]
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
        self.assertEqual(list(entry["message_keys"][0]), ["key_id", "private", "public_key", "expires_at", "signature"])
        self.assertEqual(published["fingerprint"], e2e.fingerprint(e2e.unb64(entry["identity"]["public"])))
        self.assertEqual(bob.op.keys(), published)
        self.assertEqual(bob.op.create_keys()["fingerprint"], published["fingerprint"], "a second call keeps the identity")

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

    def test_wont_publish_over_keys_another_machine_holds_even_when_their_message_key_lapsed(self):
        server = FakeServer()
        first, bob = Agent(server, encryption=True), Agent(server, encryption=True)
        first.op.create_keys()
        bob.op.create_keys()
        original = server.keys[first.id]["fingerprint"]
        server.lapsed.add(first.id)
        second = AMessage(send=server, env={}, home=Path(tempfile.mkdtemp()), token=f"agt_{first.id}", encryption=True)
        self.assertIsNone(second.keys(), "GET /v1/me/keys says nothing once the message key lapsed")
        before = len(server.puts())
        with self.assertRaises(EncryptionError) as caught:
            second.create_keys()
        self.assertEqual((caught.exception.code, caught.exception.fingerprint), ("keys_elsewhere", original))
        self.assertIn("on another machine", str(caught.exception))
        self.assertIn("replace=True", str(caught.exception))
        for attempt in (
            lambda: second.send_message({"agent_id": bob.id}, "Hi"),
            lambda: second.chat({"action": "publish_keys"}),
            second.rotate_keys,
        ):
            with self.assertRaises(EncryptionError) as refused:
                attempt()
            self.assertEqual(refused.exception.code, "keys_elsewhere")
        self.assertEqual(len(server.puts()), before, "nothing was published")
        self.assertEqual(server.keys[first.id]["fingerprint"], original)
        self.assertEqual(first.op.rotate_keys()["fingerprint"], original, "the machine that holds them publishes as before")
        replaced = second.create_keys(replace=True)
        self.assertNotEqual(replaced["fingerprint"], original)
        for attempt in (first.op.rotate_keys, first.op.create_keys):
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

    def test_makes_the_next_message_key_when_a_day_is_left_and_keeps_the_old_private_key(self):
        server = FakeServer()
        alice, bob = Agent(server, encryption=True), Agent(server, encryption=True)
        bob.op.create_keys()
        early = alice.op.send_message({"agent_id": bob.id}, "Sealed to the first key")
        everything = bob.file("keys.json")
        keys = everything[API][bob.id]["message_keys"]
        now = datetime.now(timezone.utc)
        ancient = {**keys[0], "key_id": "0" * 32, "expires_at": e2e.iso(now - timedelta(days=181))}
        keys[0]["expires_at"] = e2e.iso(now + timedelta(hours=1))
        keys.insert(0, ancient)
        (bob.dir / "keys.json").write_text(json.dumps(everything))
        before = len(server.puts())
        bob.op.read_conversation(early["conversation_id"])
        self.assertEqual(len(server.puts()), before + 1, "reading rotated the key")
        after = bob.entry()["message_keys"]
        self.assertEqual([k["key_id"] for k in after], [keys[1]["key_id"], server.keys[bob.id]["message_keys"][-1]["key_id"]])
        self.assertEqual(bob.mode("keys.json"), 0o600)
        late = alice.op.send_message({"agent_id": bob.id}, "Sealed to the next key")
        self.assertEqual(late["encrypted"]["recipient_key"], after[1]["key_id"])
        page = bob.op.read_conversation(early["conversation_id"])
        self.assertEqual([m["opened"]["text"] for m in page["data"]], ["Sealed to the next key", "Sealed to the first key"])
        bob.op.rotate_keys()
        self.assertEqual(len(bob.entry()["message_keys"]), 3)

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
        self.assertEqual(list(body), ["identity_key", "message_key"])
        self.assertEqual(list(body["message_key"]), ["key_id", "public_key", "expires_at", "signature"])
        self.assertEqual(alice.op.chat({"action": "keys"}), mine)
        bob.op.create_keys()
        theirs = alice.op.chat({"action": "agent_keys", "agent_id": bob.id})
        self.assertEqual(server.calls[-1][1], f"/v1/agents/{bob.id}/keys")
        self.assertEqual(list(theirs), ["agent_id", "identity_key", "fingerprint", "message_key", "key_changed"])
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
