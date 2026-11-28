import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { mkdtemp, readFile, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import { AMessage, AMessageError, EncryptionError } from "../index.js";
import * as e2e from "../e2e.js";

const hex = (s) => Buffer.from(s, "hex");
const VECTORS = JSON.parse(
  await readFile(new URL("../../test-vectors/encrypted-chats-vectors.json", import.meta.url), "utf8"),
);

describe("the building blocks", () => {
  it("matches draft-ietf-hpke-pq A.5: the public key, shared secret, key schedule and both messages", () => {
    const h = VECTORS.hpke;
    assert.equal(e2e.messagePublicOf(hex(h.skRm)).toString("hex"), h.pkRm);
    const schedule = e2e.inspect(hex(h.skRm), hex(h.enc), hex(h.info));
    assert.equal(schedule.shared.toString("hex"), h.shared_secret);
    assert.equal(schedule.key.toString("hex"), h.key);
    assert.equal(schedule.nonce.toString("hex"), h.base_nonce);
    assert.equal(h.encryptions.length, 2);
    for (const m of h.encryptions)
      assert.equal(e2e.openAt(hex(h.skRm), hex(h.enc), hex(h.info), hex(m.aad), hex(m.ct), hex(m.nonce)).toString("hex"), m.pt);
    // The first message is the one a single-shot open reads, with the base nonce.
    const [first] = h.encryptions;
    assert.equal(e2e.hpkeOpen(hex(h.skRm), hex(h.enc), hex(h.info), hex(first.aad), hex(first.ct)).toString("hex"), first.pt);
    const tampered = hex(first.ct);
    tampered[0] ^= 1;
    assert.throws(() => e2e.openAt(hex(h.skRm), hex(h.enc), hex(h.info), hex(first.aad), tampered, hex(first.nonce)));
    const otherEnc = hex(h.enc);
    otherEnc[otherEnc.length - 1] ^= 1;
    assert.throws(() => e2e.hpkeOpen(hex(h.skRm), otherEnc, hex(h.info), hex(first.aad), hex(first.ct)));
  });

  it("reproduces the vector file's identities, day key and signatures byte for byte, and opens its envelope", () => {
    const v = VECTORS;
    const u = e2e.unb64;
    for (const who of [v.alice_identity, v.bob_identity]) {
      assert.equal(e2e.b64(e2e.identityPublicOf(u(who.private))), who.public);
      assert.equal(e2e.fingerprint(u(who.public)), who.fingerprint);
    }
    const { private_seed, statement, ...published } = v.bob_day_key;
    assert.equal(e2e.b64(e2e.messagePublicOf(u(private_seed))), published.public_key);
    assert.equal(e2e.keyId(u(published.public_key)), published.key_id);
    assert.equal(e2e.messageKeyStatement(published.public_key, published.valid_from, published.expires_at), statement);
    assert.equal(e2e.signWith(u(v.bob_identity.private), statement), published.signature);
    // Any moment of the day gives the same day key.
    const day = e2e.messageKeyFor(u(v.bob_identity.private), u(private_seed), new Date("2026-12-01T18:00:00Z"));
    assert.equal(JSON.stringify(day.public), JSON.stringify(published));
    assert.equal(e2e.checkKeys({ ...v.bob_identity, identity_key: v.bob_identity.public, message_key: published }), true);

    assert.equal(e2e.isEnvelope(v.envelope), true);
    assert.equal(e2e.envelopeStatement(v.envelope), v.envelope_statement);
    assert.equal(e2e.associatedData(v.envelope.sender_key, v.envelope.recipient_key).toString(), v.associated_data);
    assert.equal(e2e.verifyWith(u(v.alice_identity.public), v.envelope_statement, v.envelope.sig), true);
    const payload = JSON.parse(v.plaintext_payload);
    const opened = e2e.openMessage({
      envelope: v.envelope,
      messagePrivate: u(private_seed),
      senderIdentityPublic: u(v.alice_identity.public),
      me: payload.to,
      sender: payload.from,
    });
    assert.equal(JSON.stringify(opened), v.plaintext_payload);
    assert.equal(e2e.revealMatches(opened.franking_key, opened.text, v.envelope.commitment), true);

    // Sealing the same payload again takes fresh randomness: a new seal, the same commitment.
    const again = e2e.sealMessage({
      text: payload.text,
      from: payload.from,
      to: payload.to,
      identityPrivate: u(v.alice_identity.private),
      identityPublic: u(v.alice_identity.public),
      recipientKey: published,
      now: new Date(v.sent_at),
      frankingKey: u(v.franking_key),
    });
    assert.deepEqual(Object.keys(again), Object.keys(v.envelope));
    assert.equal(again.commitment, v.envelope.commitment);
    assert.notEqual(again.enc, v.envelope.enc);
    const reopened = e2e.openMessage({
      envelope: again,
      messagePrivate: u(private_seed),
      senderIdentityPublic: u(v.alice_identity.public),
      me: payload.to,
      sender: payload.from,
    });
    assert.equal(JSON.stringify(reopened), v.plaintext_payload);
  });

  it("makes a key for each UTC day, signed with both of its dates", () => {
    const bob = e2e.generateIdentity();
    const keys = e2e.newMessageKeys(bob.privateKey, new Date("2026-12-03T10:00:00Z"));
    assert.equal(keys.length, e2e.DAYS_AHEAD);
    assert.deepEqual(
      keys.map((k) => [k.public.valid_from, k.public.expires_at]),
      Array.from({ length: 7 }, (_, i) => [
        new Date(Date.UTC(2026, 11, 3 + i)).toISOString(),
        new Date(Date.UTC(2026, 11, 4 + i)).toISOString(),
      ]),
    );
    for (const k of keys) {
      assert.equal(k.privateKey.length, e2e.SEED_BYTES);
      assert.equal(e2e.unb64(k.public.public_key).length, e2e.PUBLIC_BYTES);
      assert.equal(e2e.checkMessageKey(bob.publicKey, k.public), true);
    }
    assert.equal(new Set(keys.map((k) => k.public.key_id)).size, 7);
    assert.equal(e2e.dayStart(new Date("2026-12-03T23:59:59.999Z")).toISOString(), "2026-12-03T00:00:00.000Z");
    const [today] = keys;
    const noon = new Date(Date.parse(today.public.valid_from) + 43_200_000).toISOString();
    assert.equal(e2e.checkMessageKey(bob.publicKey, { ...today.public, valid_from: noon }), false, "not a whole day");
    assert.equal(e2e.checkMessageKey(bob.publicKey, { ...today.public, expires_at: keys[1].public.expires_at }), false);
    assert.equal(e2e.checkMessageKey(e2e.generateIdentity().publicKey, today.public), false, "someone else's signature");
    assert.equal(e2e.checkMessageKey(bob.publicKey, { ...today.public, key_id: "0".repeat(32) }), false);
  });

  it("opens a sealed message for its recipient only, and refuses every kind of tampering", () => {
    const alice = e2e.generateIdentity();
    const bob = e2e.generateIdentity();
    const [bobKey, tomorrow] = e2e.newMessageKeys(bob.privateKey);
    const envelope = e2e.sealMessage({
      text: "Can you check the build log? Ünïcödé ✓",
      from: "alice-id",
      to: "bob-id",
      identityPrivate: alice.privateKey,
      identityPublic: alice.publicKey,
      recipientKey: bobKey.public,
    });
    assert.equal(e2e.isEnvelope(envelope), true);
    assert.equal(e2e.unb64(envelope.enc).length, e2e.ENC_BYTES);
    const read = (e = envelope, me = "bob-id", sender = "alice-id", from = alice.publicKey, key = bobKey.privateKey) =>
      e2e.openMessage({ envelope: e, messagePrivate: key, senderIdentityPublic: from, me, sender });
    const payload = read();
    assert.equal(payload.text, "Can you check the build log? Ünïcödé ✓");
    assert.equal(e2e.revealMatches(payload.franking_key, "Something else", envelope.commitment), false);
    const flip = (s) => e2e.b64(Buffer.from(e2e.unb64(s).map((byte, i) => (i === 0 ? byte ^ 1 : byte))));
    const resign = (e) => {
      const { v, sig, ...unsigned } = e;
      return { ...e, sig: e2e.signWith(alice.privateKey, e2e.envelopeStatement(unsigned)) };
    };
    assert.throws(() => read({ ...envelope, ct: flip(envelope.ct) }), /signature/);
    assert.throws(() => read(resign({ ...envelope, ct: flip(envelope.ct) })), "a changed ct, signed again, still won't open");
    assert.throws(() => read(resign({ ...envelope, enc: flip(envelope.enc) })));
    assert.throws(() => read({ ...envelope, commitment: flip(envelope.commitment) }), /signature/);
    assert.throws(() => read(envelope, "carol-id"), /other agents/);
    assert.throws(() => read(envelope, "bob-id", "mallory-id"), /other agents/);
    assert.throws(() => read(envelope, "bob-id", "alice-id", bob.publicKey), /sender's key/);
    assert.throws(() => read(envelope, "bob-id", "alice-id", alice.publicKey, tomorrow.privateKey), "another day's key can't open it");
    const mallory = e2e.generateIdentity();
    const resigned = { ...envelope, sender_key: e2e.fingerprint(mallory.publicKey), sig: e2e.b64(Buffer.alloc(64)) };
    assert.throws(() => read(resigned, "bob-id", "alice-id", mallory.publicKey), /signature/);
    assert.equal(e2e.isEnvelope({ ...envelope, extra: 1 }), false);
    assert.equal(e2e.isEnvelope({ ...envelope, v: 1 }), false);
    assert.equal(e2e.isEnvelope({ ...envelope, suite: "x25519-hkdf-sha256-aes128gcm" }), false);
    assert.equal(e2e.isEnvelope({ ...envelope, enc: e2e.b64(Buffer.alloc(32)) }), false);
    assert.equal(e2e.isEnvelope({ ...envelope, sig: e2e.b64(Buffer.alloc(32)) }), false);
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
    assert.ok(Buffer.byteLength(JSON.stringify(seal("界".repeat(2000)))) <= e2e.MAX_ENVELOPE_BYTES);
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
  // Agents whose day keys ran out: no key for today to seal to, but an identity still.
  const lapsed = new Set();
  const problem = (status, code) => Response.json({ code, detail: `Refused: ${code}.` }, { status });
  /** Today's key, as GET /v1/agents/{id}/keys answers. */
  const published = (agentId) => {
    const k = lapsed.has(agentId) ? null : keys.get(agentId);
    const now = Date.now();
    const today = k?.message_keys
      .filter((m) => Date.parse(m.valid_from) <= now && Date.parse(m.expires_at) > now)
      .sort((a, b) => Date.parse(b.valid_from) - Date.parse(a.valid_from))[0];
    return today && { agent_id: agentId, identity_key: k.identity_key, fingerprint: k.fingerprint, message_key: today };
  };
  const keysUntil = (agentId) =>
    new Date(Math.max(...keys.get(agentId).message_keys.map((m) => Date.parse(m.expires_at)))).toISOString();
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
    if (path === "/v1/me") {
      const encryption = keys.has(me) ? { fingerprint: keys.get(me).fingerprint } : null;
      return Response.json({ agent_id: me, inbox_id: me, name: null, linked_to_account: false, encryption });
    }
    if (path === "/v1/me/keys" && method === "PUT") {
      const identity = e2e.unb64(body.identity_key);
      const fingerprint = e2e.fingerprint(identity);
      const days = body.message_keys;
      if (identity.length !== 32 || !Array.isArray(days) || !days.length || days.length > 14)
        return problem(400, "bad_request");
      if (!days.every((m) => e2e.checkMessageKey(identity, m) && Date.parse(m.expires_at) > Date.now()))
        return problem(400, "bad_request");
      const before = keys.get(me);
      // A new identity key replaces the old one, and the old one's day keys stop taking messages.
      if (!before || before.identity_key !== body.identity_key)
        keys.set(me, { identity_key: body.identity_key, fingerprint, message_keys: [] });
      const held = keys.get(me).message_keys;
      for (const m of days) if (!held.some((k) => k.key_id === m.key_id)) held.push(m);
      lapsed.delete(me);
      return published(me) ? Response.json(published(me)) : problem(400, "bad_request");
    }
    if (path === "/v1/me/keys")
      return published(me) ? Response.json({ ...published(me), keys_until: keysUntil(me) }) : problem(404, "not_found");
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
        const now = Date.now();
        const usable = (recipient?.message_keys ?? []).filter(
          (k) => Date.parse(k.expires_at) + e2e.DAY_MS > now && Date.parse(k.valid_from) <= now + e2e.DAY_MS,
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
  return { fetch, calls, keys, phones, conversations, messages, reports, refuseNext, lapsed };
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
    assert.equal(entry.message_keys.length, 7, "a key for each of the next 7 days");
    assert.deepEqual(Object.keys(entry.message_keys[0]), [
      "key_id",
      "private",
      "public_key",
      "valid_from",
      "expires_at",
      "signature",
    ]);
    const today = e2e.dayStart(new Date()).getTime();
    assert.deepEqual(
      entry.message_keys.map((k) => k.valid_from),
      Array.from({ length: 7 }, (_, i) => new Date(today + i * e2e.DAY_MS).toISOString()),
    );
    for (const k of entry.message_keys) assert.equal(e2e.unb64(k.private).length, e2e.SEED_BYTES);
    const put = server.calls.findLast((c) => c.method === "PUT" && c.path === "/v1/me/keys");
    assert.deepEqual(Object.keys(put.body), ["identity_key", "message_keys"]);
    assert.deepEqual(
      put.body.message_keys,
      entry.message_keys.map(({ private: _, ...half }) => half),
      "the public halves of all 7 days, in order",
    );
    assert.equal(published.fingerprint, e2e.fingerprint(e2e.unb64(entry.identity.public)));
    assert.equal(published.message_key.key_id, entry.message_keys[0].key_id, "today's key");
    assert.deepEqual(await bob.op.keys(), { ...published, keys_until: entry.message_keys[6].expires_at });
    assert.equal((await bob.op.createKeys()).fingerprint, published.fingerprint, "a second call keeps the identity");
    assert.deepEqual(
      (await json(file))["https://api.amessage.sh"][bob.id].message_keys.map((k) => k.key_id),
      entry.message_keys.map((k) => k.key_id),
      "and makes no new keys for days it has",
    );

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

  it("won't publish over keys another machine holds, even when their day keys ran out, unless told to replace them", async () => {
    const server = fakeServer();
    const first = await agent(server, { encryption: true });
    const bob = await agent(server, { encryption: true });
    await first.op.createKeys();
    await bob.op.createKeys();
    const original = server.keys.get(first.id).fingerprint;
    server.lapsed.add(first.id);
    const second = new AMessage({
      fetch: server.fetch,
      env: {},
      home: await mkdtemp(join(tmpdir(), "amessage-e2e-")),
      token: `agt_${first.id}`,
      encryption: true,
    });
    assert.equal(await second.keys(), null, "GET /v1/me/keys says nothing without a key for today");
    const puts = () => server.calls.filter((c) => c.method === "PUT" && c.path === "/v1/me/keys").length;
    const before = puts();
    await assert.rejects(second.createKeys(), (error) => {
      assert.ok(error instanceof EncryptionError);
      assert.equal(error.code, "keys_elsewhere");
      assert.equal(error.fingerprint, original);
      assert.match(error.message, /on another machine/);
      assert.match(error.message, /replace: true/);
      return true;
    });
    await assert.rejects(second.sendMessage({ agent_id: bob.id }, "Hi"), { code: "keys_elsewhere" });
    await assert.rejects(second.chat({ action: "publish_keys" }), { code: "keys_elsewhere" });
    assert.equal(puts(), before, "nothing was published");
    assert.equal(server.keys.get(first.id).fingerprint, original);
    // The machine that holds them publishes as before.
    assert.equal((await first.op.createKeys()).fingerprint, original);
    // replace: true takes them over, and then the first machine can't take them back unasked.
    const replaced = await second.createKeys({ replace: true });
    assert.notEqual(replaced.fingerprint, original);
    await assert.rejects(first.op.createKeys(), { code: "keys_elsewhere" });
    await assert.rejects(first.op.chat({ action: "publish_keys" }), { code: "keys_elsewhere" });
    assert.equal(server.keys.get(first.id).fingerprint, replaced.fingerprint);
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

  it("publishes the next days when fewer than 3 are left, keeps private day keys 180 days, and drops version 1 keys", async () => {
    const server = fakeServer();
    const alice = await agent(server, { encryption: true });
    const bob = await agent(server, { encryption: true });
    await bob.op.createKeys();
    const early = await alice.op.sendMessage({ agent_id: bob.id }, "Sealed to today's key");
    const file = join(bob.dir, "keys.json");
    const puts = () => server.calls.filter((c) => c.method === "PUT" && c.path === "/v1/me/keys");
    const all = await json(file);
    const keys = all["https://api.amessage.sh"][bob.id].message_keys;
    const today = keys[0];
    // Three days left: nothing to publish yet.
    all["https://api.amessage.sh"][bob.id].message_keys = keys.slice(0, 4);
    await writeFile(file, JSON.stringify(all));
    let before = puts().length;
    await bob.op.readConversation(early.conversation_id);
    assert.equal(puts().length, before, "three days left is enough");
    // Two days left, an ancient key and a key of version 1: reading publishes, and tidies.
    const ancient = { ...today, key_id: "0".repeat(32), valid_from: new Date(Date.now() - 182 * e2e.DAY_MS).toISOString(), expires_at: new Date(Date.now() - 181 * e2e.DAY_MS).toISOString() };
    const kept = { ...today, key_id: "1".repeat(32), valid_from: new Date(Date.now() - 171 * e2e.DAY_MS).toISOString(), expires_at: new Date(Date.now() - 170 * e2e.DAY_MS).toISOString() };
    const version1 = { key_id: "2".repeat(32), private: today.private, public_key: "abc", expires_at: new Date(Date.now() + e2e.DAY_MS).toISOString(), signature: "abc" };
    all["https://api.amessage.sh"][bob.id].message_keys = [version1, ancient, kept, ...keys.slice(0, 2)];
    all["https://api.amessage.sh"][bob.id].pins = { [alice.id]: "a".repeat(64) };
    await writeFile(file, JSON.stringify(all));
    before = puts().length;
    const page = await bob.op.readConversation(early.conversation_id);
    assert.deepEqual(page.data[0].opened, { text: "Sealed to today's key", verified: false, reason: "their key changed since your first chat" }, "pins stayed");
    assert.equal(puts().length, before + 1, "reading published the next days");
    const published = puts().at(-1).body.message_keys;
    assert.equal(published.length, 7);
    assert.deepEqual(published.slice(0, 2).map((k) => k.key_id), keys.slice(0, 2).map((k) => k.key_id), "the days it had, again");
    const after = (await json(file))["https://api.amessage.sh"][bob.id];
    assert.deepEqual(Object.keys(after), ["identity", "message_keys", "pins"]);
    assert.deepEqual(
      after.message_keys.map((k) => k.key_id),
      [kept.key_id, ...published.map((k) => k.key_id)],
      "version 1 and 181-day-old keys are gone; one 170 days old stays",
    );
    assert.equal(await mode(file), 0o600);
    // Sealed to a later day's key, it opens with that key.
    const aliceIdentity = (await json(join(alice.dir, "keys.json")))["https://api.amessage.sh"][alice.id].identity;
    const later = e2e.sealMessage({
      text: "Sealed to tomorrow's key",
      from: alice.id,
      to: bob.id,
      identityPrivate: e2e.unb64(aliceIdentity.private),
      identityPublic: e2e.unb64(aliceIdentity.public),
      recipientKey: after.message_keys[2],
    });
    await bob.op.trustKey(alice.id);
    assert.deepEqual(await bob.op.open({ id: randomUUID(), encrypted: later, sender_agent_id: alice.id }), {
      text: "Sealed to tomorrow's key",
      verified: true,
    });
  });

  it("drops a replayed envelope, but reads the same message again as often as asked", async () => {
    const server = fakeServer();
    const alice = await agent(server, { encryption: true });
    const bob = await agent(server, { encryption: true });
    await bob.op.createKeys();
    const sent = await alice.op.sendMessage({ agent_id: bob.id }, "Pay invoice 42");
    const first = await bob.op.readConversation(sent.conversation_id);
    const again = await bob.op.readConversation(sent.conversation_id);
    assert.deepEqual(first.data[0].opened, { text: "Pay invoice 42", verified: true });
    assert.deepEqual(again.data[0].opened, first.data[0].opened, "a second read is no replay");
    assert.deepEqual((await bob.op.chat({ action: "read", id: sent.id })).opened, first.data[0].opened);
    const seenFile = join(bob.dir, "seen.json");
    assert.equal(await mode(seenFile), 0o600);
    const seen = (await json(seenFile))["https://api.amessage.sh"][bob.id];
    assert.deepEqual(Object.keys(seen), [sent.encrypted.commitment]);
    assert.deepEqual(Object.keys(seen[sent.encrypted.commitment]), ["message_id", "opened_at"]);
    assert.equal(seen[sent.encrypted.commitment].message_id, sent.id);

    // Someone posts the same envelope again: it reads as a copy, and the original still reads.
    const copy = { ...server.messages.get(sent.id), id: randomUUID(), posted_at: new Date(Date.now() + 1000).toISOString() };
    server.messages.set(copy.id, copy);
    const page = await bob.op.readConversation(sent.conversation_id);
    assert.deepEqual(
      page.data.map((m) => [m.id, m.opened]),
      [
        [copy.id, { text: null, verified: false, reason: "a copy of a message already opened" }],
        [sent.id, { text: "Pay invoice 42", verified: true }],
      ],
    );
    assert.equal((await bob.op.chat({ action: "read", id: copy.id })).opened.text, null);
    assert.deepEqual(await bob.op.open(copy), { text: null, verified: false, reason: "a copy of a message already opened" });
    // A request carries its message's id, so it reads as that message.
    const request = { id: randomUUID(), message_id: sent.id, sender: { agent_id: alice.id }, encrypted: sent.encrypted, text: null };
    assert.deepEqual(await bob.op.open(request), { text: "Pay invoice 42", verified: true });
    // An incoming request still waiting has no message id yet: a fresh envelope reads, and is only
    // remembered once its message is read; one opened before is a replay.
    const waiting = { id: randomUUID(), direction: "incoming", sender: { agent_id: alice.id }, text: null };
    const fresh = await alice.op.seal({ agent_id: bob.id }, "Lunch on Friday?");
    assert.deepEqual(await bob.op.open({ ...waiting, encrypted: fresh }), { text: "Lunch on Friday?", verified: true });
    assert.deepEqual(await bob.op.open({ ...waiting, encrypted: fresh }), { text: "Lunch on Friday?", verified: true });
    assert.deepEqual(await bob.op.open({ ...waiting, encrypted: sent.encrypted }), {
      text: null,
      verified: false,
      reason: "a copy of a message already opened",
    });
    await assert.rejects(bob.op.reportConversation(sent.conversation_id, "spam", { reveal: [copy.id] }), { code: "cant_open" });
    assert.deepEqual(Object.keys((await json(seenFile))["https://api.amessage.sh"][bob.id]), [sent.encrypted.commitment]);

    // Seen for the first time in one page, the older of two copies is the one that reads.
    await writeFile(seenFile, "{}");
    const firstTime = await bob.op.readConversation(sent.conversation_id);
    assert.deepEqual(firstTime.data.map((m) => m.opened.text), [null, "Pay invoice 42"]);
    // Entries older than 180 days are dropped when it next writes.
    const old = { "https://api.amessage.sh": { [bob.id]: { stale: { message_id: "m", opened_at: new Date(Date.now() - 181 * e2e.DAY_MS).toISOString() } } } };
    await writeFile(seenFile, JSON.stringify(old));
    await bob.op.readConversation(sent.conversation_id);
    assert.deepEqual(Object.keys((await json(seenFile))["https://api.amessage.sh"][bob.id]), [sent.encrypted.commitment]);
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
    assert.deepEqual(Object.keys(put.body), ["identity_key", "message_keys"]);
    assert.equal(put.body.message_keys.length, 7);
    assert.deepEqual(Object.keys(put.body.message_keys[0]), ["key_id", "public_key", "valid_from", "expires_at", "signature"]);
    const shown = await alice.op.chat({ action: "keys" });
    assert.deepEqual(shown, { ...mine, keys_until: put.body.message_keys[6].expires_at });
    await bob.op.createKeys();
    const theirs = await alice.op.chat({ action: "agent_keys", agent_id: bob.id });
    assert.equal(server.calls.at(-1).path, `/v1/agents/${bob.id}/keys`);
    assert.deepEqual(Object.keys(theirs), ["agent_id", "identity_key", "fingerprint", "message_key", "key_changed"]);
    assert.ok(Date.parse(theirs.message_key.valid_from) <= Date.now() && Date.now() < Date.parse(theirs.message_key.expires_at));
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
