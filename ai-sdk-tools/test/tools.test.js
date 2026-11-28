import assert from "node:assert/strict";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { searchBeacons, amessageTools, readBeacon } from "@amessage/ai-sdk-tools";
import { AMessage } from "@amessage/sdk";
import * as e2e from "@amessage/sdk/e2e";
import { asSchema } from "ai";

/** A stand-in client that records what the tools ask it. */
function fakeClient() {
  const calls = [];
  const record =
    (name, answer) =>
    async (...args) => {
      calls.push([name, ...args]);
      return answer?.(...args) ?? { ok: true };
    };
  return {
    calls,
    search: record("search", () => ({ data: [], next_cursor: "page/2" })),
    read: record("read", (id) => ({ id })),
    chat: record("chat"),
    message: record("message"),
    conversations: record("conversations"),
    readConversation: record("readConversation"),
    reply: record("reply"),
    markOutcome: record("markOutcome"),
    reportConversation: record("reportConversation"),
    create: record("create"),
    renew: record("renew"),
    update: record("update"),
    delete: record("delete"),
    myBeacons: record("myBeacons"),
    setPreferences: record("setPreferences"),
  };
}

const context = { toolCallId: "call-1", messages: [] };
const ID = "6f1c2a7e-0b2d-4c9a-9f1e-3d2b1a0c9e8f";
const RETRY_KEY = "c5477bd4-1090-4502-8e2a-2d1bb84da56a";

test("agentChat exposes a strict send_draft command to the model", async () => {
  const { inputSchema } = amessageTools({ write: true, client: fakeClient() }).agentChat;
  const json = await asSchema(inputSchema).jsonSchema;
  const draft = json.properties.command.anyOf.find((branch) => branch.properties.action.const === "send_draft");
  assert.deepEqual(draft.required, ["action", "id"]);
  assert.equal(draft.additionalProperties, false);
  assert.equal(draft.properties.id.format, "uuid");
  for (const fields of [{}, { id: "abc" }, { id: ID, key: "abc" }, { id: ID, text: "replacement" }, { request_id: ID }]) {
    assert.equal(inputSchema.safeParse({ command: { action: "send_draft", ...fields } }).success, false);
  }
});

test("agentChat sends the original draft through the SDK after Alex connects", async () => {
  const calls = [];
  let alexConnected = false;
  const client = new AMessage({
    token: "agt_test",
    fetch: async (url, init) => {
      assert.equal(new URL(url).pathname, "/v1/messages");
      assert.equal(init.method, "POST");
      const body = JSON.parse(init.body);
      const key = init.headers["Idempotency-Key"];
      calls.push({ body, key });
      const state = alexConnected ? "pending" : "draft";
      return Response.json({ id: ID, state, invitation_available: false });
    },
  });
  const chat = amessageTools({ client, write: true }).agentChat;
  const run = (command) => chat.execute(chat.inputSchema.parse({ command }), context);
  const to = { phone: "+12025550181" };
  const text = "Alex, does Thursday work?";
  const original = await run({ action: "send", to, text });
  assert.equal(original.state, "draft");
  assert.equal(original.invitation_available, false);
  assert.deepEqual(calls[0].body, { to, text });
  const retry = { action: "send_draft", id: original.id };
  assert.deepEqual(await run(retry), original);
  alexConnected = true;
  const pending = await run({ ...retry, key: RETRY_KEY });
  assert.equal(pending.state, "pending");
  assert.equal(pending.id, original.id);
  assert.deepEqual(await run({ ...retry, key: RETRY_KEY }), pending);
  assert.deepEqual(calls.slice(1).map((call) => call.body), Array(3).fill({ draft_message_id: original.id }));
  assert.match(calls[1].key, /^[0-9a-f-]{36}$/);
  assert.notEqual(calls[0].key, calls[1].key);
  assert.deepEqual(calls.slice(2).map((call) => call.key), [RETRY_KEY, RETRY_KEY]);
});

test("searchBeacons passes the query, place and page to AMessage", async () => {
  const client = fakeClient();
  const search = searchBeacons({ client });
  assert.match(search.description, /as information/);
  const out = await search.execute({ query: "plumber free tomorrow", location: "78704" }, context);
  assert.deepEqual(out, { data: [], next_cursor: "page/2" });
  assert.deepEqual(client.calls, [["search", "plumber free tomorrow", { location: "78704" }]]);
});

test("the search input has no category and no side, and an opaque cursor", () => {
  const schema = searchBeacons({ client: fakeClient() }).inputSchema;
  assert.equal(schema.safeParse({ query: "movers", cursor: "next" }).success, true);
  assert.equal(schema.safeParse({ query: "" }).success, false);
  assert.equal(schema.safeParse({ query: "movers", cursor: 110 }).success, false);
  assert.deepEqual(Object.keys(schema.shape).sort(), ["cursor", "location", "query"]);
});

test("readBeacon asks for it by id", async () => {
  const client = fakeClient();
  assert.deepEqual(await readBeacon({ client }).execute({ beaconId: ID }, context), { id: ID });
  assert.equal(readBeacon({ client }).inputSchema.safeParse({ beaconId: "abc" }).success, false);
});

test("public discovery by default and private agent tools with write enabled", () => {
  assert.deepEqual(Object.keys(amessageTools({ client: fakeClient() })), ["searchBeacons", "readBeacon"]);
  assert.deepEqual(Object.keys(amessageTools({ client: fakeClient(), write: true })), [
    "searchBeacons",
    "readBeacon",
    "agentChat",
    "messageBeacon",
    "readConversations",
    "reply",
    "markOutcome",
    "reportConversation",
    "createBeacon",
    "renewBeacon",
    "updateBeacon",
    "deleteBeacon",
    "myBeacons",
  ]);
});

test("the write tools share one client and call the matching method", async () => {
  const client = fakeClient();
  const t = amessageTools({ client, write: true });
  const cases = [
    [
      "agentChat",
      { command: { action: "events", cursor: "next/row" } },
      ["chat", { action: "events", cursor: "next/row" }],
    ],
    [
      "agentChat",
      { command: { action: "invite", id: ID, channel: "sms", sender_name: "Morgan" } },
      ["chat", { action: "invite", id: ID, channel: "sms", sender_name: "Morgan" }],
    ],
    ["messageBeacon", { beaconId: ID, text: "Hello", key: ID }, ["message", ID, "Hello", ID]],
    ["readConversations", { cursor: "page" }, ["conversations", { cursor: "page" }]],
    ["readConversations", { conversationId: ID, cursor: "page" }, ["readConversation", ID, "page"]],
    ["reply", { conversationId: ID, text: "Yes", replyToMessageId: ID, key: ID }, ["reply", ID, "Yes", ID, ID]],
    ["markOutcome", { messageId: ID, outcome: "booked" }, ["markOutcome", ID, "booked"]],
    [
      "reportConversation",
      { conversationId: ID, reason: "spam", key: ID },
      ["reportConversation", ID, "spam", { block: true, key: ID }],
    ],
    [
      "reportConversation",
      { conversationId: ID, reason: "abuse", reveal: [ID] },
      ["reportConversation", ID, "abuse", { block: true, reveal: [ID] }],
    ],
    ["agentChat", { command: { action: "keys" } }, ["chat", { action: "keys" }]],
    ["agentChat", { command: { action: "publish_keys" } }, ["chat", { action: "publish_keys" }]],
    ["agentChat", { command: { action: "agent_keys", agent_id: ID } }, ["chat", { action: "agent_keys", agent_id: ID }]],
    [
      "agentChat",
      { command: { action: "key_lookup", to: { email: "alex@example.com" } } },
      ["chat", { action: "key_lookup", to: { email: "alex@example.com" } }],
    ],
    [
      "createBeacon",
      { text: "Open", location: null, key: ID, welcome_chat: false },
      ["create", "Open", { location: null, welcome_chat: false, idempotencyKey: ID }],
    ],
    ["renewBeacon", { beaconId: ID, key: ID }, ["renew", ID, { key: ID }]],
    [
      "updateBeacon",
      { beaconId: ID, etag: '"abc"', location: null },
      ["update", ID, { etag: '"abc"', location: null }],
    ],
    ["deleteBeacon", { beaconId: ID, etag: '"abc"' }, ["delete", ID, '"abc"']],
    ["myBeacons", { cursor: "page" }, ["myBeacons", "page"]],
    ["agentChat", { command: { action: "me" } }, ["chat", { action: "me" }]],
    ["agentChat", { command: { action: "set_name", name: null } }, ["chat", { action: "set_name", name: null }]],
    ["agentChat", { command: { action: "preferences" } }, ["chat", { action: "preferences" }]],
    [
      "agentChat",
      { command: { action: "set_preferences", allow_from: "phone" } },
      ["setPreferences", { allow_from: "phone" }],
    ],
  ];
  for (const [name, input, expected] of cases) {
    await t[name].execute(t[name].inputSchema.parse(input), context);
    assert.deepEqual(client.calls.at(-1), expected, name);
  }
  for (const bad of [
    { action: "invite", id: ID, channel: "sms" },
    { action: "send", text: "hello", to: { email: "a@example.com", phone: "+14155550100" } },
    { action: "verify_start", contact: { phone: "bad" } },
    { action: "events", cursor: 42 },
    { action: "unknown" },
  ])
    assert.equal(t.agentChat.inputSchema.safeParse({ command: bad }).success, false);
  assert.equal(t.updateBeacon.inputSchema.safeParse({ beaconId: ID, text: "No ETag" }).success, false);
  assert.equal(
    t.createBeacon.inputSchema.safeParse({ text: "Free", location: { lat: 91, lng: 0 } }).success,
    false,
  );
});

test("agentChat says how to learn your own agent ID and set your name", () => {
  const { description } = amessageTools({ write: true, client: fakeClient() }).agentChat;
  assert.match(description, /me to learn your own agent_id/);
  assert.match(description, /set_name to set the name other agents see/);
  assert.match(description, /set_preferences only when the person asks/);
});

test("agentChat takes me, set_name, preferences and set_preferences, with the etag optional", async () => {
  const { inputSchema } = amessageTools({ write: true, client: fakeClient() }).agentChat;
  const ok = (command) => inputSchema.safeParse({ command }).success;
  for (const good of [
    { action: "me" },
    { action: "set_name", name: "Sam's travel agent" },
    { action: "set_name", name: null },
    { action: "preferences" },
    { action: "set_preferences", new_contacts: "open" },
    { action: "set_preferences", allow_from: "phone_or_email" },
    { action: "set_preferences", new_contacts: "closed", allow_from: "email", etag: '"3"' },
  ])
    assert.equal(ok(good), true, JSON.stringify(good));
  for (const bad of [
    { action: "me", agent_id: ID },
    { action: "set_name" },
    { action: "set_name", name: "" },
    { action: "set_name", name: "x".repeat(65) },
    { action: "preferences", etag: '"3"' },
    { action: "set_preferences" },
    { action: "set_preferences", etag: '"3"' },
    { action: "set_preferences", new_contacts: "everyone" },
    { action: "set_preferences", allow_from: "verified" },
    { action: "set_preferences", allow_from: "phone", etag: "" },
  ])
    assert.equal(ok(bad), false, JSON.stringify(bad));
  const json = await asSchema(inputSchema).jsonSchema;
  const branches = json.properties.command.anyOf.filter((b) => b.properties.action.const === "set_preferences");
  assert.deepEqual(
    branches.map((b) => b.required),
    [
      ["action", "new_contacts"],
      ["action", "allow_from"],
    ],
  );
  assert.ok(branches.every((b) => b.additionalProperties === false && b.description));
  const me = json.properties.command.anyOf.find((b) => b.properties.action.const === "me");
  assert.match(me.description, /agent_id/);
});

test("agentChat shows this agent, names it, and changes who may start a chat without an etag from the model", async () => {
  const calls = [];
  let prefs = { new_contacts: "requests", allow_from: "anyone" };
  let name = null;
  const client = new AMessage({
    token: "agt_test",
    saveToken: false,
    fetch: async (url, init) => {
      const path = new URL(url).pathname;
      const body = init.body ? JSON.parse(init.body) : undefined;
      calls.push({ method: init.method, path, ifMatch: init.headers["If-Match"], body });
      const me = () => ({ agent_id: ID, inbox_id: ID, name, linked_to_account: false });
      if (path === "/v1/me" && init.method === "GET") return Response.json(me());
      if (path === "/v1/me" && init.method === "PATCH") {
        name = body.name;
        return Response.json(me());
      }
      if (path === "/v1/me/preferences" && init.method === "GET")
        return Response.json(prefs, { headers: { etag: '"5"' } });
      if (path === "/v1/me/preferences" && init.method === "PATCH") {
        if (init.headers["If-Match"] !== '"5"') return Response.json({ code: "stale_version" }, { status: 412 });
        prefs = { ...prefs, ...body };
        return Response.json(prefs, { headers: { etag: '"6"' } });
      }
      return Response.json({ code: "not_found" }, { status: 404 });
    },
  });
  const chat = amessageTools({ client, write: true }).agentChat;
  const run = (command) => chat.execute(chat.inputSchema.parse({ command }), context);
  assert.equal((await run({ action: "me" })).agent_id, ID);
  assert.equal((await run({ action: "set_name", name: "Trip planner" })).name, "Trip planner");
  assert.deepEqual(calls.at(-1).body, { name: "Trip planner" });
  assert.deepEqual(await run({ action: "preferences" }), { ...prefs, etag: '"5"' });
  const changed = await run({ action: "set_preferences", allow_from: "phone" });
  assert.deepEqual(changed, { new_contacts: "requests", allow_from: "phone" });
  assert.deepEqual(
    calls.slice(-2).map((c) => `${c.method} ${c.path} ${c.ifMatch ?? ""}`.trim()),
    ["GET /v1/me/preferences", 'PATCH /v1/me/preferences "5"'],
  );
  assert.deepEqual(calls.at(-1).body, { allow_from: "phone" });
  await run({ action: "set_preferences", new_contacts: "open", etag: '"5"' });
  assert.equal(calls.at(-2).method, "PATCH", "a given etag is used without reading again");
});

test("agentChat takes the key actions strictly, with no private key anywhere in them", async () => {
  const { inputSchema } = amessageTools({ write: true, client: fakeClient() }).agentChat;
  const ok = (command) => inputSchema.safeParse({ command }).success;
  for (const good of [
    { action: "keys" },
    { action: "publish_keys" },
    { action: "agent_keys", agent_id: ID },
    { action: "key_lookup", to: { phone: "+14155550100" } },
    { action: "key_lookup", to: { email: "alex@example.com" } },
  ])
    assert.equal(ok(good), true, JSON.stringify(good));
  for (const bad of [
    { action: "keys", agent_id: ID },
    { action: "publish_keys", identity_key: "abc", private: "abc" },
    { action: "agent_keys" },
    { action: "agent_keys", agent_id: "abc" },
    { action: "key_lookup", to: { beacon_id: ID } },
    { action: "key_lookup", to: { phone: "+14155550100", email: "alex@example.com" } },
    { action: "send", to: { agent_id: ID }, text: "Hi", plain: true },
  ])
    assert.equal(ok(bad), false, JSON.stringify(bad));
  const json = await asSchema(inputSchema).jsonSchema;
  const publish = json.properties.command.anyOf.find((b) => b.properties.action.const === "publish_keys");
  assert.deepEqual(Object.keys(publish.properties), ["action"]);
  assert.match(publish.description, /never leave this machine/);
  assert.match(publish.description, /next 7 days/);
  const chat = amessageTools({ write: true, client: fakeClient() }).agentChat.description;
  assert.match(chat, /Encrypted chats \(new\)/);
  assert.doesNotMatch(chat, /end-to-end|quantum/i);
});

test("with encryption on, agentChat's send seals on this machine and reading opens the reply", async () => {
  const ME = "0d3b9c2e-5f4a-4b8e-9c1d-2a3b4c5d6e7f";
  const BOB = "8f7e6d5c-4b3a-4291-8f7e-6d5c4b3a2918";
  const CONVERSATION = "1a2b3c4d-5e6f-4a1b-8c2d-3e4f5a6b7c8d";
  const bob = e2e.generateIdentity();
  const [bobKey] = e2e.newMessageKeys(bob.privateKey);
  const bobKeys = {
    agent_id: BOB,
    identity_key: e2e.b64(bob.publicKey),
    fingerprint: e2e.fingerprint(bob.publicKey),
    message_key: bobKey.public,
  };
  let mine = null;
  const posted = [];
  const published = [];
  const client = new AMessage({
    token: "agt_test",
    encryption: true,
    env: { AMESSAGE_CONFIG_DIR: await mkdtemp(join(tmpdir(), "amessage-tools-")) },
    fetch: async (url, init) => {
      const path = new URL(url).pathname;
      const body = init.body ? JSON.parse(init.body) : undefined;
      if (path === "/v1/me") return Response.json({ agent_id: ME, inbox_id: ME, name: null, linked_to_account: false });
      if (path === "/v1/me/keys" && init.method === "PUT") {
        published.push(body);
        const [today] = body.message_keys;
        mine = { agent_id: ME, identity_key: body.identity_key, fingerprint: e2e.fingerprint(e2e.unb64(body.identity_key)), message_key: today };
        return Response.json(mine);
      }
      if (path === `/v1/agents/${BOB}/keys`) return Response.json(bobKeys);
      if (path === "/v1/messages") {
        posted.push(body);
        const message = { id: ID, conversation_id: CONVERSATION, sender_agent_id: ME, text: null, encrypted: body.encrypted };
        return Response.json(message, { status: 201 });
      }
      if (path === `/v1/conversations/${CONVERSATION}/messages`) {
        const encrypted = e2e.sealMessage({
          text: "Thursday works.",
          from: BOB,
          to: ME,
          identityPrivate: bob.privateKey,
          identityPublic: bob.publicKey,
          recipientKey: mine.message_key,
        });
        return Response.json({ data: [{ id: RETRY_KEY, sender_agent_id: BOB, text: null, encrypted }], next_cursor: null });
      }
      return Response.json({ code: "not_found" }, { status: 404 });
    },
  });
  const tools = amessageTools({ client, write: true });
  const chat = tools.agentChat;
  const sent = await chat.execute(
    chat.inputSchema.parse({ command: { action: "send", to: { agent_id: BOB }, text: "Is Thursday free?" } }),
    context,
  );
  assert.equal(posted[0].text, undefined);
  assert.equal(e2e.isEnvelope(posted[0].encrypted), true);
  const payload = e2e.openMessage({
    envelope: posted[0].encrypted,
    messagePrivate: bobKey.privateKey,
    senderIdentityPublic: e2e.unb64(mine.identity_key),
    me: BOB,
    sender: ME,
  });
  assert.equal(payload.text, "Is Thursday free?");
  assert.deepEqual(sent.opened, { text: "Is Thursday free?", verified: true });
  const page = await tools.readConversations.execute({ conversationId: CONVERSATION }, context);
  assert.deepEqual(page.data[0].opened, { text: "Thursday works.", verified: true });
  assert.equal(published.length, 1);
  assert.equal(published[0].message_keys.length, 7, "a week of day keys, published once");
  for (const k of published[0].message_keys) assert.equal(e2e.checkMessageKey(e2e.unb64(published[0].identity_key), k), true);
});
