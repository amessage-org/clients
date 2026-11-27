import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { mkdtemp, readFile, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import { AMessage, AMessageError, EncryptionError } from "../index.js";
import * as e2e from "../e2e.js";

const hex = (s) => Buffer.from(s.replace(/\s/g, ""), "hex");
const VECTORS = JSON.parse(
  await readFile(new URL("../../test-vectors/encrypted-chats-vectors.json", import.meta.url), "utf8"),
);

// RFC 9180, Appendix A.1: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM, base mode.
const A1 = {
  info: hex("4f6465206f6e2061204772656369616e2055726e"),
  ikmE: hex("7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234"),
  pkEm: "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431",
  skEm: "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736",
  ikmR: hex("6db9df30aa07dd42ee5e8181afdb977e538f5e1fec8a06223f33f7013e525037"),
  pkRm: "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d",
  skRm: "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8",
  sharedSecret: "fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc",
  key: "4531685d41d65f03dc48f6b8302c05b0",
  baseNonce: "56d890e5accaaf011cff4b7d",
  pt: hex("4265617574792069732074727574682c20747275746820626561757479"),
  aad: hex("436f756e742d30"),
  ct: "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a",
};

describe("the building blocks", () => {
  it("matches RFC 9180 A.1: derived keys, shared secret, key schedule and the first seal", () => {
    const e = e2e.deriveX25519(A1.ikmE);
    const r = e2e.deriveX25519(A1.ikmR);
    assert.equal(e.publicKey.toString("hex"), A1.pkEm);
    assert.equal(e.privateKey.toString("hex"), A1.skEm);
    assert.equal(r.publicKey.toString("hex"), A1.pkRm);
    assert.equal(r.privateKey.toString("hex"), A1.skRm);
    const sealed = e2e.hpkeSeal(r.publicKey, A1.info, A1.aad, A1.pt, e);
    assert.equal(sealed.enc.toString("hex"), A1.pkEm);
    const schedule = e2e.inspect(sealed.enc, r.privateKey, A1.info);
    assert.equal(schedule.shared.toString("hex"), A1.sharedSecret);
    assert.equal(schedule.key.toString("hex"), A1.key);
    assert.equal(schedule.nonce.toString("hex"), A1.baseNonce);
    assert.equal(sealed.ct.toString("hex"), A1.ct);
    assert.deepEqual(e2e.hpkeOpen(r.privateKey, sealed.enc, A1.info, A1.aad, sealed.ct), A1.pt);
    const tampered = Buffer.from(sealed.ct);
    tampered[0] ^= 1;
    assert.throws(() => e2e.hpkeOpen(r.privateKey, sealed.enc, A1.info, A1.aad, tampered));
  });

  it("seals the spec's test vectors to the same envelope, byte for byte, and opens them to the payload", () => {
    const v = VECTORS;
    const u = e2e.unb64;
    for (const who of [v.alice_identity, v.bob_identity]) {
      assert.equal(e2e.b64(e2e.identityPublicOf(u(who.private))), who.public);
      assert.equal(e2e.fingerprint(u(who.public)), who.fingerprint);
    }
    const bobKey = v.bob_message_key;
    assert.equal(e2e.b64(e2e.x25519PublicOf(u(bobKey.private))), bobKey.public_key);
    assert.equal(e2e.keyId(u(bobKey.public_key)), bobKey.key_id);
    assert.equal(
      e2e.signWith(u(v.bob_identity.private), e2e.messageKeyStatement(bobKey.public_key, bobKey.expires_at)),
      bobKey.signature,
    );
    assert.equal(e2e.checkKeys({ ...v.bob_identity, identity_key: v.bob_identity.public, message_key: bobKey }), true);
    const payload = JSON.parse(v.plaintext_payload);
    const ephemeral = u(v.ephemeral_private);
    const envelope = e2e.sealMessage({
      text: payload.text,
      from: payload.from,
      to: payload.to,
      identityPrivate: u(v.alice_identity.private),
      identityPublic: u(v.alice_identity.public),
      recipientKey: bobKey,
      now: new Date(v.sent_at),
      ephemeral: { privateKey: ephemeral, publicKey: e2e.x25519PublicOf(ephemeral) },
      frankingKey: u(v.franking_key),
    });
    assert.equal(JSON.stringify(envelope), JSON.stringify(v.envelope));
    assert.equal(e2e.isEnvelope(envelope), true);
    const opened = e2e.openMessage({
      envelope: v.envelope,
      messagePrivate: u(bobKey.private),
      senderIdentityPublic: u(v.alice_identity.public),
      me: payload.to,
      sender: payload.from,
    });
    assert.equal(JSON.stringify(opened), v.plaintext_payload);
    assert.equal(e2e.revealMatches(opened.franking_key, opened.text, v.envelope.commitment), true);
  });

  it("opens a sealed message for its recipient only, and refuses every kind of tampering", () => {
    const alice = e2e.generateIdentity();
    const bob = e2e.generateIdentity();
    const bobKey = e2e.newMessageKey(bob.privateKey);
    const envelope = e2e.sealMessage({
      text: "Can you check the build log? Ünïcödé ✓",
      from: "alice-id",
      to: "bob-id",
      identityPrivate: alice.privateKey,
      identityPublic: alice.publicKey,
      recipientKey: bobKey.public,
    });
    const read = (e = envelope, me = "bob-id", sender = "alice-id", from = alice.publicKey) =>
      e2e.openMessage({ envelope: e, messagePrivate: bobKey.privateKey, senderIdentityPublic: from, me, sender });
    const payload = read();
    assert.equal(payload.text, "Can you check the build log? Ünïcödé ✓");
    assert.equal(e2e.revealMatches(payload.franking_key, "Something else", envelope.commitment), false);
    const flip = (s) => e2e.b64(Buffer.from(e2e.unb64(s).map((byte, i) => (i === 0 ? byte ^ 1 : byte))));
    assert.throws(() => read({ ...envelope, ct: flip(envelope.ct) }));
    assert.throws(() => read({ ...envelope, commitment: flip(envelope.commitment) }), /signature/);
    assert.throws(() => read(envelope, "carol-id"), /other agents/);
    assert.throws(() => read(envelope, "bob-id", "mallory-id"), /other agents/);
    assert.throws(() => read(envelope, "bob-id", "alice-id", bob.publicKey), /sender's key/);
    const mallory = e2e.generateIdentity();
    const resigned = { ...envelope, sender_key: e2e.fingerprint(mallory.publicKey), sig: e2e.b64(Buffer.alloc(64)) };
    assert.throws(() => read(resigned, "bob-id", "alice-id", mallory.publicKey), /signature/);
    assert.equal(e2e.isEnvelope({ ...envelope, extra: 1 }), false);
    assert.equal(e2e.isEnvelope({ ...envelope, v: 2 }), false);
    const seal = (text) =>
      e2e.sealMessage({
        text,
        from: "a",
        to: "b",
        identityPrivate: alice.privateKey,
        identityPublic: alice.publicKey,
        recipientKey: bobKey.public,
      });
    // 2,000 characters fit in any script; 2,001 don't.
    assert.ok(Buffer.byteLength(JSON.stringify(seal("😀".repeat(2000)))) <= e2e.MAX_ENVELOPE_BYTES);
    assert.throws(() => seal("a".repeat(2001)), RangeError);
  });

  it("exports an agent's keys with a passphrase, and only that passphrase imports them", () => {
    const entry = { identity: { private: "p", public: "q" }, message_keys: [], pins: {} };
    const sealed = e2e.exportKeys(entry, "correct horse battery staple");
    assert.deepEqual(Object.keys(sealed), ["v", "kdf", "n", "r", "p", "salt", "nonce", "ct"]);
    assert.deepEqual([sealed.v, sealed.kdf, sealed.n, sealed.r, sealed.p], [1, "scrypt", 32768, 8, 1]);
    assert.equal(e2e.unb64(sealed.salt).length, 16);
    assert.equal(e2e.unb64(sealed.nonce).length, 12);
    assert.deepEqual(e2e.importKeys(sealed, "correct horse battery staple"), entry);
    assert.throws(() => e2e.importKeys(sealed, "wrong"), /Wrong passphrase/);
  });
});

/**
 * A stand-in for the aMessage API's chat and key calls, for several agents at once. It checks
 * envelopes as the server does (shape, the sender's signature, the recipient's key) and never
 * opens one.
 */
function fakeServer() {
  const tokens = new Map();
  const keys = new Map();
  const phones = new Map();
  const conversations = new Map();
  const messages = new Map();
  const reports = [];
  const calls = [];
  const refuseNext = [];
  const problem = (status, code) => Response.json({ code, detail: `Refused: ${code}.` }, { status });
  const published = (agentId) => {
    const k = keys.get(agentId);
    return k && { agent_id: agentId, identity_key: k.identity_key, fingerprint: k.fingerprint, message_key: k.message_keys.at(-1) };
  };
  const chatBetween = (a, b) => {
    for (const c of conversations.values()) if (c.agents.includes(a) && c.agents.includes(b)) return c;
    const c = { id: randomUUID(), agents: [a, b], encrypted: false };
    conversations.set(c.id, c);
    return c;
  };
  const fetch = async (url, init = {}) => {
    const u = new URL(url);
    const method = init.method ?? "GET";
    const path = u.pathname;
    const body = init.body ? JSON.parse(init.body) : undefined;
    calls.push({ method, path, body, headers: init.headers ?? {} });
    if (path === "/v1/agents" && method === "POST") {
      const agent = randomUUID();
      const token = `agt_${agent}`;
      tokens.set(token, agent);
      return Response.json({ agent: { agent_id: agent, inbox_id: agent, linked_to_account: false }, token }, { status: 201 });
    }
    const me = tokens.get((init.headers?.Authorization ?? "").replace("Bearer ", ""));
    if (!me) return problem(401, "connect_first");
    if (path === "/v1/me") return Response.json({ agent_id: me, inbox_id: me, name: null, linked_to_account: false });
    if (path === "/v1/me/keys" && method === "PUT") {
      const fingerprint = e2e.fingerprint(e2e.unb64(body.identity_key));
      if (!e2e.checkKeys({ ...body, fingerprint })) return problem(422, "invalid_keys");
      const before = keys.get(me);
      if (!before || before.identity_key !== body.identity_key)
        keys.set(me, { identity_key: body.identity_key, fingerprint, message_keys: [body.message_key] });
      else if (before.message_keys.at(-1).key_id !== body.message_key.key_id) before.message_keys.push(body.message_key);
      return Response.json(published(me));
    }
    if (path === "/v1/me/keys") return keys.has(me) ? Response.json(published(me)) : problem(404, "not_found");
    const agentKeys = path.match(/^\/v1\/agents\/([^/]+)\/keys$/);
    if (agentKeys) {
      const answer = published(decodeURIComponent(agentKeys[1]));
      return answer ? Response.json(answer) : problem(404, "not_found");
    }
    if (path === "/v1/key-lookups") {
      const answer = published(phones.get(body.to.phone) ?? phones.get(body.to.email));
      return answer ? Response.json(answer) : problem(404, "not_found");
    }
    const conversation = path.match(/^\/v1\/conversations\/([^/]+)(\/messages|\/reports)?$/);
    if (conversation) {
      const c = conversations.get(conversation[1]);
      if (!c || !c.agents.includes(me)) return problem(404, "not_found");
      if (!conversation[2])
        return Response.json({ id: c.id, counterpart: { agent_id: c.agents.find((a) => a !== me) }, encrypted: c.encrypted });
      if (conversation[2] === "/messages") {
        const data = [...messages.values()].filter((m) => m.conversation_id === c.id).reverse();
        return Response.json({ data, next_cursor: null });
      }
      for (const shown of body.reveal ?? []) {
        const m = messages.get(shown.message_id);
        if (!m?.encrypted || !e2e.revealMatches(shown.franking_key, shown.text, m.encrypted.commitment))
          return problem(422, "reveal_mismatch");
      }
      reports.push(body);
      return Response.json({ id: randomUUID(), blocked: body.block }, { status: 201 });
    }
    const message = path.match(/^\/v1\/messages\/([^/]+)$/);
    if (message) return messages.has(message[1]) ? Response.json(messages.get(message[1])) : problem(404, "not_found");
    if (path === "/v1/messages" && method === "POST") {
      const refusal = refuseNext.shift();
      if (refusal) return problem(409, refusal);
      const to = body.to;
      const other = to.agent_id ?? phones.get(to.phone) ?? conversations.get(to.conversation_id)?.agents.find((a) => a !== me);
      if (!other) return problem(404, "not_found");
      const c = chatBetween(me, other);
      if (body.encrypted !== undefined) {
        const env = body.encrypted;
        const sender = keys.get(me);
        const recipient = keys.get(other);
        if (!e2e.isEnvelope(env) || body.text !== undefined) return problem(422, "invalid_envelope");
        if (!sender || env.sender_key !== sender.fingerprint) return problem(409, "stale_key");
        if (!e2e.verifyWith(e2e.unb64(sender.identity_key), e2e.envelopeStatement(env), env.sig))
          return problem(422, "invalid_envelope");
        const usable = (recipient?.message_keys ?? []).filter(
          (k) => Date.parse(k.expires_at) + e2e.DAY_MS > Date.now(),
        );
        if (!usable.some((k) => k.key_id === env.recipient_key)) return problem(409, "stale_key");
        c.encrypted = true;
      } else if (c.encrypted) return problem(409, "encrypted_chat");
      const m = {
        id: randomUUID(),
        state: "posted",
        request_id: null,
        conversation_id: c.id,
        sender_agent_id: me,
        authored_by: "agent",
        text: body.encrypted ? null : body.text,
        encrypted: body.encrypted ?? null,
        reply_to_message_id: body.reply_to_message_id ?? null,
        created_at: new Date().toISOString(),
        posted_at: new Date().toISOString(),
        beacon_id: null,
      };
      messages.set(m.id, m);
      return Response.json(m, { status: 201 });
    }
    return problem(404, "not_found");
  };
  return { fetch, calls, keys, phones, conversations, messages, reports, refuseNext };
}

async function agent(server, options = {}) {
  const home = await mkdtemp(join(tmpdir(), "amessage-e2e-"));
  const op = new AMessage({ fetch: server.fetch, env: {}, home, ...options });
  await op.connect();
  const dir = join(home, ".config/amessage");
  const id = JSON.parse(await readFile(join(dir, "credentials.json"), "utf8"))["https://api.amessage.sh"].agent_id;
  return { op, home, dir, id };
}
const json = async (file) => JSON.parse(await readFile(file, "utf8"));
const mode = async (file) => (await stat(file)).mode & 0o777;
const sends = (server) => server.calls.filter((c) => c.method === "POST" && c.path === "/v1/messages");

describe("encrypted chats between two agents", () => {
  it("keeps keys.json beside credentials.json, seals by itself, and opens what it reads", async () => {
    const server = fakeServer();
    const alice = await agent(server, { encryption: true });
    const bob = await agent(server, { encryption: true });
    const published = await bob.op.createKeys();
    assert.equal(published.agent_id, bob.id);
    const file = join(bob.dir, "keys.json");
    assert.equal(await mode(file), 0o600);
    const entry = (await json(file))["https://api.amessage.sh"][bob.id];
    assert.deepEqual(Object.keys(entry), ["identity", "message_keys", "pins"]);
    assert.deepEqual(Object.keys(entry.identity), ["private", "public"]);
    assert.deepEqual(Object.keys(entry.message_keys[0]), ["key_id", "private", "public_key", "expires_at", "signature"]);
    assert.equal(published.fingerprint, e2e.fingerprint(e2e.unb64(entry.identity.public)));
    assert.deepEqual(await bob.op.keys(), published);
    assert.equal((await bob.op.createKeys()).fingerprint, published.fingerprint, "a second call keeps the identity");

    const sent = await alice.op.sendMessage({ agent_id: bob.id }, "Can you check the build log?");
    assert.equal(sent.text, null);
    assert.ok(e2e.isEnvelope(sent.encrypted));
    assert.deepEqual(sent.opened, { text: "Can you check the build log?", verified: true });
    const post = sends(server).at(-1);
    assert.equal(post.body.text, undefined);
    assert.deepEqual(post.body.to, { agent_id: bob.id });
    assert.ok(post.headers["Idempotency-Key"]);
    // Alice had no keys: encryption: true made and published them first.
    assert.ok(server.keys.has(alice.id));
    const aliceKeys = (await json(join(alice.dir, "keys.json")))["https://api.amessage.sh"][alice.id];
    assert.deepEqual(aliceKeys.pins, { [bob.id]: published.fingerprint });
    const copies = await json(join(alice.dir, "sent.json"));
    assert.equal(await mode(join(alice.dir, "sent.json")), 0o600);
    assert.deepEqual(Object.keys(copies["https://api.amessage.sh"][alice.id][sent.id]), ["text", "sent_at"]);

    const page = await bob.op.readConversation(sent.conversation_id);
    assert.equal(page.data[0].text, null);
    assert.deepEqual(page.data[0].encrypted, sent.encrypted);
    assert.deepEqual(page.data[0].opened, { text: "Can you check the build log?", verified: true });
    assert.deepEqual((await bob.op.chat({ action: "read", id: sent.id })).opened, page.data[0].opened);

    const reply = await bob.op.reply(sent.conversation_id, "Yes, on it.", sent.id);
    assert.ok(reply.encrypted, "a reply in the conversation is sealed to its other agent");
    const history = await alice.op.readConversation(sent.conversation_id);
    assert.deepEqual(
      history.data.map((m) => m.opened),
      [
        { text: "Yes, on it.", verified: true },
        { text: "Can you check the build log?", verified: true },
      ],
    );
    // The same agent on a machine without the copy can't read what it sent.
    const elsewhere = new AMessage({
      fetch: server.fetch,
      env: {},
      home: await mkdtemp(join(tmpdir(), "amessage-e2e-")),
      token: `agt_${alice.id}`,
    });
    const there = await elsewhere.readConversation(sent.conversation_id);
    assert.deepEqual(there.data[1].opened, { text: null, verified: false, reason: "sent from another machine" });
    assert.equal(there.data[0].opened.text, null, "no keys on that machine");

    // No private key ever left either machine.
    const privates = [];
    for (const who of [alice, bob]) {
      const e = (await json(join(who.dir, "keys.json")))["https://api.amessage.sh"][who.id];
      privates.push(e.identity.private, ...e.message_keys.map((k) => k.private));
    }
    const wire = JSON.stringify(server.calls.map((c) => c.body ?? null));
    for (const secret of privates) assert.equal(wire.includes(secret), false);
  });

  it("sends plain with plain: true or to an agent with no keys, and refuses plain only where it must", async () => {
    const server = fakeServer();
    const alice = await agent(server, { encryption: true });
    const bob = await agent(server);
    const carol = await agent(server);
    await bob.op.createKeys();
    const plain = await alice.op.sendMessage({ agent_id: carol.id }, "Hello Carol");
    assert.equal(plain.text, "Hello Carol");
    assert.equal(plain.opened, undefined);
    assert.equal(sends(server).at(-1).body.text, "Hello Carol");
    await assert.rejects(alice.op.sendMessage({ agent_id: carol.id }, "Hi", { encrypted: true }), {
      name: "EncryptionError",
      code: "no_keys",
    });
    await alice.op.sendMessage({ agent_id: bob.id }, "Sealed");
    await assert.rejects(alice.op.sendMessage({ agent_id: bob.id }, "Not sealed", { plain: true }), (error) => {
      assert.ok(error instanceof AMessageError);
      assert.equal(error.code, "encrypted_chat");
      return true;
    });
    // Without the option, a client sends plain unless told to seal.
    const quiet = await agent(server);
    await quiet.op.sendMessage({ agent_id: carol.id }, "Plain");
    assert.equal(sends(server).at(-1).body.text, "Plain");
    const insisted = await quiet.op.sendMessage({ agent_id: bob.id }, "Sealed anyway", { encrypted: true });
    assert.ok(insisted.encrypted);
    // A beacon's owner can't be known, so it gets plain words.
    await assert.rejects(alice.op.chat({ action: "send", to: { beacon_id: randomUUID() }, text: "Hi" }), { status: 404 });
    assert.deepEqual(sends(server).at(-1).body, { to: sends(server).at(-1).body.to, text: "Hi" });
  });

  it("stops sealing to a partner whose key changed until trustKey, and shows its messages as unverified", async () => {
    const server = fakeServer();
    const alice = await agent(server, { encryption: true });
    const bob = await agent(server, { encryption: true });
    await bob.op.createKeys();
    const first = await alice.op.sendMessage({ agent_id: bob.id }, "Before the change");
    const old = (await alice.op.agentKeys(bob.id)).fingerprint;
    const renewed = await bob.op.createKeys({ replace: true });
    assert.notEqual(renewed.fingerprint, old);
    assert.equal((await bob.op.readConversation(first.conversation_id)).data[0].opened.text, "Before the change");

    await assert.rejects(alice.op.sendMessage({ agent_id: bob.id }, "After"), (error) => {
      assert.ok(error instanceof EncryptionError);
      assert.equal(error.code, "key_changed");
      assert.equal(error.pinned, old);
      assert.equal(error.fingerprint, renewed.fingerprint);
      assert.match(error.message, /trustKey/);
      return true;
    });
    const posts = sends(server).length;
    await assert.rejects(alice.op.seal({ agent_id: bob.id }, "After"), { code: "key_changed" });
    assert.equal(sends(server).length, posts, "nothing was sent");
    assert.equal((await alice.op.agentKeys(bob.id)).key_changed, true);
    await bob.op.sendMessage({ agent_id: alice.id }, "New key, same Bob");
    const page = await alice.op.readConversation(first.conversation_id);
    assert.deepEqual(page.data[0].opened, {
      text: "New key, same Bob",
      verified: false,
      reason: "their key changed since your first chat",
    });
    await assert.rejects(alice.op.trustKey(bob.id, old), { code: "fingerprint_mismatch" });
    assert.equal((await alice.op.trustKey(bob.id, renewed.fingerprint)).key_changed, false);
    assert.ok((await alice.op.sendMessage({ agent_id: bob.id }, "After")).encrypted);
    assert.equal((await alice.op.readConversation(first.conversation_id)).data[1].opened.verified, true);
  });

  it("makes the next message key when a day is left, keeps the old private key, and drops long-ended ones", async () => {
    const server = fakeServer();
    const alice = await agent(server, { encryption: true });
    const bob = await agent(server, { encryption: true });
    await bob.op.createKeys();
    const early = await alice.op.sendMessage({ agent_id: bob.id }, "Sealed to the first key");
    const file = join(bob.dir, "keys.json");
    const all = await json(file);
    const keys = all["https://api.amessage.sh"][bob.id].message_keys;
    const ancient = { ...keys[0], key_id: "0".repeat(32), expires_at: new Date(Date.now() - 181 * e2e.DAY_MS).toISOString() };
    keys[0].expires_at = new Date(Date.now() + 3_600_000).toISOString();
    keys.unshift(ancient);
    await writeFile(file, JSON.stringify(all));
    const puts = () => server.calls.filter((c) => c.method === "PUT" && c.path === "/v1/me/keys").length;
    const before = puts();
    await bob.op.readConversation(early.conversation_id);
    assert.equal(puts(), before + 1, "reading rotated the key");
    const after = (await json(file))["https://api.amessage.sh"][bob.id].message_keys;
    assert.deepEqual(
      after.map((k) => k.key_id),
      [keys[1].key_id, server.keys.get(bob.id).message_keys.at(-1).key_id],
    );
    assert.equal(await mode(file), 0o600);
    const late = await alice.op.sendMessage({ agent_id: bob.id }, "Sealed to the next key");
    assert.equal(late.encrypted.recipient_key, after[1].key_id);
    const page = await bob.op.readConversation(early.conversation_id);
    assert.deepEqual(
      page.data.map((m) => m.opened.text),
      ["Sealed to the next key", "Sealed to the first key"],
    );
    await bob.op.rotateKeys();
    assert.equal((await json(file))["https://api.amessage.sh"][bob.id].message_keys.length, 3);
  });

  it("finds keys by phone, seals without sending, and opens one message", async () => {
    const server = fakeServer();
    const alice = await agent(server);
    const bob = await agent(server);
    const phone = "+14155550100";
    server.phones.set(phone, bob.id);
    assert.equal(await alice.op.lookupKeys({ phone }), null);
    await bob.op.createKeys();
    await alice.op.createKeys();
    const found = await alice.op.lookupKeys({ phone });
    assert.equal(found.agent_id, bob.id);
    assert.equal(found.key_changed, false);
    assert.equal(server.calls.at(-1).path, "/v1/key-lookups");
    assert.deepEqual(server.calls.at(-1).body, { to: { phone } });
    const envelope = await alice.op.seal({ phone }, "Sealed by hand");
    assert.deepEqual(await bob.op.open({ encrypted: envelope, sender_agent_id: alice.id }), {
      text: "Sealed by hand",
      verified: true,
    });
    assert.deepEqual(await bob.op.open({ encrypted: envelope, sender_agent_id: randomUUID() }), {
      text: null,
      verified: false,
      reason: "the sender's keys couldn't be read",
    });
    assert.equal(await bob.op.open({ text: "plain", encrypted: null }), null);
    const sent = await alice.op.chat({ action: "send", to: { phone }, encrypted: envelope });
    assert.deepEqual(sends(server).at(-1).body, { to: { phone }, encrypted: envelope });
    assert.deepEqual(sent.opened, { text: "Sealed by hand", verified: true });
    const copy = (await json(join(alice.dir, "sent.json")))["https://api.amessage.sh"][alice.id][sent.id];
    assert.equal(copy.text, "Sealed by hand");
    // A request carries the envelope too, with its sender and message_id.
    const request = { id: randomUUID(), message_id: sent.id, sender: { agent_id: alice.id }, encrypted: envelope, text: null };
    assert.deepEqual(await bob.op.open(request), { text: "Sealed by hand", verified: true });
    assert.deepEqual(await alice.op.open(request), { text: "Sealed by hand", verified: true }, "from sent.json");
  });

  it("on stale_key fetches the keys again, publishes its own and seals once more with the same write key", async () => {
    const server = fakeServer();
    const alice = await agent(server, { encryption: true });
    const bob = await agent(server, { encryption: true });
    await bob.op.createKeys();
    server.refuseNext.push("stale_key");
    const sent = await alice.op.sendMessage({ agent_id: bob.id }, "Try twice", { key: "retry-key" });
    assert.ok(sent.encrypted);
    const posts = sends(server);
    assert.deepEqual(
      posts.map((c) => c.headers["Idempotency-Key"]),
      ["retry-key", "retry-key"],
    );
    server.refuseNext.push("stale_key", "stale_key");
    await assert.rejects(alice.op.sendMessage({ agent_id: bob.id }, "Never"), { code: "stale_key" });
  });

  it("chats keys, publish_keys, agent_keys and key_lookup as calls to the key endpoints", async () => {
    const server = fakeServer();
    const alice = await agent(server);
    const bob = await agent(server);
    assert.equal(await alice.op.chat({ action: "keys" }), null);
    assert.equal(await alice.op.chat({ action: "agent_keys", agent_id: bob.id }), null);
    const mine = await alice.op.chat({ action: "publish_keys" });
    const put = server.calls.at(-1);
    assert.equal(`${put.method} ${put.path}`, "PUT /v1/me/keys");
    assert.deepEqual(Object.keys(put.body), ["identity_key", "message_key"]);
    assert.deepEqual(Object.keys(put.body.message_key), ["key_id", "public_key", "expires_at", "signature"]);
    assert.deepEqual(await alice.op.chat({ action: "keys" }), mine);
    await bob.op.createKeys();
    const theirs = await alice.op.chat({ action: "agent_keys", agent_id: bob.id });
    assert.equal(server.calls.at(-1).path, `/v1/agents/${bob.id}/keys`);
    assert.deepEqual(Object.keys(theirs), ["agent_id", "identity_key", "fingerprint", "message_key", "key_changed"]);
    server.phones.set("bob@example.com", bob.id);
    assert.equal((await alice.op.chat({ action: "key_lookup", to: { email: "bob@example.com" } })).agent_id, bob.id);
    await assert.rejects(alice.op.chat({ action: "key_lookup" }), /requires to/);
    // Keys that don't check are refused, not pinned.
    server.keys.get(bob.id).fingerprint = "f".repeat(64);
    await assert.rejects(alice.op.agentKeys(bob.id), { code: "bad_keys" });
  });

  it("reports with reveal: opens the messages here and sends their text and franking keys", async () => {
    const server = fakeServer();
    const alice = await agent(server, { encryption: true });
    const bob = await agent(server, { encryption: true });
    await bob.op.createKeys();
    const rude = await alice.op.sendMessage({ agent_id: bob.id }, "Something abusive");
    await bob.op.reportConversation(rude.conversation_id, "abuse", { reveal: [rude.id], key: "report-key" });
    assert.equal(server.reports.length, 1);
    const [shown] = server.reports[0].reveal;
    assert.equal(shown.message_id, rude.id);
    assert.equal(shown.text, "Something abusive");
    assert.ok(e2e.revealMatches(shown.franking_key, shown.text, rude.encrypted.commitment));
    assert.equal(server.calls.at(-1).headers["Idempotency-Key"], "report-key");
    await assert.rejects(alice.op.reportConversation(rude.conversation_id, "spam", { reveal: [rude.id] }), {
      code: "cant_open",
    });
    await bob.op.reportConversation(rude.conversation_id, "spam");
    assert.deepEqual(server.reports.at(-1), { reason: "spam", block: true });
  });
});
