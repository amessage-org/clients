import assert from "node:assert/strict";
import { mkdtemp, readFile, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import { AMessage, AMessageError } from "../index.js";

const PAGE = { data: [], next_cursor: "next" };
const BEACON = {
  id: "b1",
  url: "https://amessage.sh/beacon/b1",
  beacon: {
    text: "Free tomorrow 9–12 for leaks and clogs",
    location: { lat: 30.2416, lng: -97.7695, updated: "2026-10-19T16:00:00Z" },
    expires: "2026-10-19T17:00:00Z",
  },
  verification: {
    issuer: "amessage.sh",
    description: "Nothing about who made this was checked. Active 1 day. Never reported.",
  },
  mine: {
    closed: false,
    renew_from: "2026-10-19T16:45:00Z",
    deletes_at: null,
    revision: null,
    latest: { revision: 1, text: "Free tomorrow 9–12 for leaks and clogs", safety: "pending", reason: null },
    conversations_waiting: 0,
  },
};

/**
 * A stand-in for the AMessage API: records each call and answers like the beacon
 * contract. Searching and reading need no token; a token that is sent must be valid.
 */
function fakeApi({ tokens = ["agt_first", "agt_second"], refuse = null } = {}) {
  const calls = [];
  const valid = new Set();
  const fetch = async (url, init = {}) => {
    const u = new URL(url);
    const method = init.method ?? "GET";
    calls.push({ method, path: u.pathname + u.search, headers: init.headers ?? {}, body: init.body });
    const body = init.body ? JSON.parse(init.body) : undefined;
    if (u.pathname === "/v1/agents") {
      const token = tokens.shift();
      valid.add(token);
      return Response.json(
        { agent: { agent_id: "a1", inbox_id: "a1", linked_to_account: false }, token },
        { status: 201 },
      );
    }
    if (refuse) return refuse();
    const bearer = (init.headers?.Authorization ?? "").replace("Bearer ", "");
    if (bearer && !valid.has(bearer))
      return Response.json({ code: "connect_first", detail: "Connect first." }, { status: 401 });
    if (u.pathname === "/v1/beacons" && method === "GET") return Response.json(PAGE);
    if (u.pathname === "/v1/beacons/b1" && method === "GET") return Response.json(BEACON);
    if (!bearer) return Response.json({ code: "connect_first", detail: "Connect first." }, { status: 401 });
    if (u.pathname === "/v1/beacons")
      return Response.json({ id: "b1", published: BEACON, latest_revision: 1, etag: '"1"' }, { status: 201 });
    if (u.pathname.endsWith("/b1/messages"))
      return Response.json(
        { note: "…", conversation: { id: "c1", beacon_revision: 2, about: "sent" } },
        { status: 201 },
      );
    return Response.json({ ok: true, path: u.pathname, body });
  };
  return { fetch, calls };
}

async function client(api, extra = {}) {
  const home = await mkdtemp(join(tmpdir(), "amessage-js-"));
  return { home, op: new AMessage({ fetch: api.fetch, env: {}, home, ...extra }) };
}

const exists = (file) =>
  stat(file).then(
    () => true,
    () => false,
  );

describe("searching and reading beacons", () => {
  it("searches and reads with no token and without connecting", async () => {
    const api = fakeApi();
    const { home, op } = await client(api);
    const page = await op.search("plumber free tomorrow", { location: "78704", cursor: "page/two" });
    assert.deepEqual(page, PAGE);
    assert.deepEqual(await op.read("b1"), BEACON);
    assert.deepEqual(
      api.calls.map((c) => `${c.method} ${c.path}`),
      ["GET /v1/beacons?q=plumber+free+tomorrow&location=78704&cursor=page%2Ftwo", "GET /v1/beacons/b1"],
    );
    assert.equal(api.calls[0].headers.Authorization, undefined);
    assert.equal(api.calls[0].headers.Accept, "application/json");
    assert.equal(await exists(join(home, ".config/amessage/credentials.json")), false);
  });

  it("sends a token it already has, and searches without it when it was revoked", async () => {
    const api = fakeApi();
    const { home, op } = await client(api);
    await op.myBeacons();
    await new AMessage({ fetch: api.fetch, env: {}, home }).search("movers");
    assert.equal(api.calls.at(-1).headers.Authorization, "Bearer agt_first");
    const stale = new AMessage({
      fetch: api.fetch,
      env: {},
      home: await mkdtemp(join(tmpdir(), "amessage-js-")),
      token: "agt_revoked",
    });
    assert.deepEqual(await stale.search("movers"), PAGE);
    assert.equal(api.calls.at(-1).headers.Authorization, undefined);
    assert.equal(api.calls.filter((c) => c.path === "/v1/agents").length, 1);
  });

  it("uses AMESSAGE_TOKEN before the saved token", async () => {
    const api = fakeApi();
    const home = await mkdtemp(join(tmpdir(), "amessage-js-"));
    await new AMessage({ fetch: api.fetch, env: { AMESSAGE_TOKEN: "agt_env" }, home }).search("movers");
    assert.equal(api.calls[0].headers.Authorization, "Bearer agt_env");
  });
});

describe("connecting", () => {
  it("connects with no body on the first call that needs a token, saves it, and reuses it", async () => {
    const api = fakeApi();
    const { home, op } = await client(api);
    await op.myBeacons();
    const connect = api.calls[0];
    assert.equal(`${connect.method} ${connect.path}`, "POST /v1/agents");
    assert.equal(connect.body, undefined);
    assert.equal(connect.headers["Content-Type"], undefined);
    assert.equal(api.calls[1].headers.Authorization, "Bearer agt_first");
    const saved = JSON.parse(await readFile(join(home, ".config/amessage/credentials.json"), "utf8"));
    assert.deepEqual(Object.keys(saved["https://api.amessage.sh"]).sort(), ["agent_id", "connected_at", "token"]);
    await new AMessage({ fetch: api.fetch, env: {}, home }).myBeacons();
    assert.equal(api.calls.filter((c) => c.path === "/v1/agents").length, 1);
  });

  it("sends the agent's name when it connects, if given one", async () => {
    const api = fakeApi();
    const { op } = await client(api, { name: " Build bot " });
    await op.myBeacons();
    assert.deepEqual(JSON.parse(api.calls[0].body), { name: "Build bot" });
    assert.equal(api.calls[0].headers["Content-Type"], "application/json");
  });

  it("reports a revoked private identity without creating a different agent", async () => {
    const api = fakeApi();
    const { op } = await client(api, { token: "agt_revoked" });
    await assert.rejects(op.myBeacons(), { status: 401 });
    assert.deepEqual(
      api.calls.map((c) => c.path),
      ["/v1/me/beacons"],
    );
    assert.equal(await op.known(), "agt_revoked");
  });
});

describe("a business's own beacons", () => {
  it("creates, renews, updates and deletes a beacon, with the fields the contract takes and no others", async () => {
    const api = fakeApi();
    const { op } = await client(api);
    const point = { lat: 30.2416, lng: -97.7695 };
    const created = await op.create("Free tomorrow 9–12 for leaks and clogs", {
      location: point,
      idempotencyKey: "k1",
    });
    assert.equal(created.id, "b1");
    assert.equal(created.latest_revision, 1);
    const create = api.calls.at(-1);
    assert.equal(`${create.method} ${create.path}`, "POST /v1/beacons");
    assert.deepEqual(JSON.parse(create.body), { text: "Free tomorrow 9–12 for leaks and clogs", location: point });
    assert.equal(create.headers["Idempotency-Key"], "k1");
    await op.create("Remote bookkeeping help, evenings.");
    assert.deepEqual(JSON.parse(api.calls.at(-1).body), { text: "Remote bookkeeping help, evenings." });
    await op.create("Remote bookkeeping help, evenings.", { location: null });
    assert.deepEqual(JSON.parse(api.calls.at(-1).body), {
      text: "Remote bookkeeping help, evenings.",
      location: null,
    });
    assert.throws(() => op.create("Free tomorrow", { location: "78704" }), TypeError);
    await op.renew("b1", { key: "renew-retry-key" });
    assert.equal(api.calls.at(-1).path, "/v1/beacons/b1/renewals");
    assert.equal(api.calls.at(-1).headers["Idempotency-Key"], "renew-retry-key");
    await op.update("b1", { etag: created.etag, text: "Free tomorrow 10–12 only", location: null });
    const changed = api.calls.at(-1);
    assert.equal(changed.method, "PATCH");
    assert.equal(changed.headers["If-Match"], '"1"');
    assert.deepEqual(JSON.parse(changed.body), { text: "Free tomorrow 10–12 only", location: null });
    await op.delete("b1", '"2"');
    assert.equal(api.calls.at(-1).headers["If-Match"], '"2"');
    await op.myBeacons("next/page");
    assert.equal(api.calls.at(-1).path, "/v1/me/beacons?cursor=next%2Fpage");
    await op.setTakingMessages(false, '"7"');
    assert.equal(api.calls.at(-1).path, "/v1/me/preferences");
    assert.equal(api.calls.at(-1).headers["If-Match"], '"7"');
  });
});

describe("a beacon on the move", () => {
  it("sends only the location as a point with the revision, and renew can carry it too", async () => {
    const api = fakeApi();
    const { op } = await client(api);
    await op.updateLocation("b1", 30.2672, -97.7431, '"3"');
    assert.deepEqual(JSON.parse(api.calls.at(-1).body), { location: { lat: 30.2672, lng: -97.7431 } });
    await op.renew("b1", { location: { lat: 30.27, lng: -97.74 } });
    assert.deepEqual(JSON.parse(api.calls.at(-1).body), { location: { lat: 30.27, lng: -97.74 } });
  });

  it("says how long to wait when it was sent sooner than 3 seconds", async () => {
    const api = fakeApi({
      refuse: () =>
        Response.json(
          {
            code: "rate_limited",
            detail: "This beacon’s location was updated less than 3 seconds ago.",
            next: "Send its location at most once every 3 seconds.",
          },
          { status: 429, headers: { "Retry-After": "2" } },
        ),
    });
    const { op } = await client(api, { token: "agt_env" });
    await assert.rejects(op.updateLocation("b1", 30.2672, -97.7431, '"3"'), (error) => {
      assert.ok(error instanceof AMessageError);
      assert.equal(error.status, 429);
      assert.equal(error.code, "rate_limited");
      assert.equal(error.retryAfter, 2);
      return true;
    });
  });
});

describe("messages and conversations", () => {
  it("messages a beacon, lists and reads conversations, replies, marks the outcome and reports", async () => {
    const api = fakeApi();
    const { op } = await client(api);
    await op.message("b1", "Can you come at 10?", "send-key");
    assert.deepEqual(JSON.parse(api.calls.at(-1).body), { to: { beacon_id: "b1" }, text: "Can you come at 10?" });
    await op.conversations({ cursor: "opaque/two" });
    assert.equal(api.calls.at(-1).path, "/v1/conversations?cursor=opaque%2Ftwo");
    await op.readConversation("c1");
    assert.equal(api.calls.at(-1).path, "/v1/conversations/c1/messages");
    await op.reply("c1", "Yes", "m1", "retry-key");
    assert.equal(api.calls.at(-1).path, "/v1/messages");
    assert.equal(api.calls.at(-1).headers["Idempotency-Key"], "retry-key");
    assert.deepEqual(JSON.parse(api.calls.at(-1).body), {
      to: { conversation_id: "c1" },
      text: "Yes",
      reply_to_message_id: "m1",
    });
    await op.events("snapshot/+");
    assert.equal(api.calls.at(-1).path, "/v1/events?cursor=snapshot%2F%2B");
    await op.invite("r1", "sms", "Maya");
    assert.equal(api.calls.at(-1).path, "/v1/requests/r1/invitation");
    await op.markOutcome("m1", "booked");
    assert.equal(api.calls.at(-1).path, "/v1/messages/m1/outcome");
    await op.reportConversation("c1", "spam");
    assert.equal(api.calls.at(-1).path, "/v1/conversations/c1/reports");
  });

  it("says why AMessage refused, what to do next, and how long to wait", async () => {
    const next = "Tell the person, and offer others.";
    const api = fakeApi({
      refuse: () =>
        Response.json(
          { code: "beacon_closed", detail: "This beacon expired: its creator didn’t renew it.", next },
          { status: 410, headers: { "Retry-After": "30" } },
        ),
    });
    const { op } = await client(api);
    await assert.rejects(op.message("b1", "Hi"), (error) => {
      assert.ok(error instanceof AMessageError);
      assert.equal(error.status, 410);
      assert.equal(error.code, "beacon_closed");
      assert.equal(error.next, next);
      assert.equal(error.retryAfter, 30);
      assert.equal(error.message, `This beacon expired: its creator didn’t renew it. ${next}`);
      return true;
    });
  });

  it("names the app first in the User-Agent", async () => {
    const api = fakeApi();
    const { op } = await client(api, { app: "JobFinder/1.0" });
    await op.search("line cook jobs in Austin");
    assert.match(api.calls[0].headers["User-Agent"], /^JobFinder\/1\.0 amessage-js\/0\.6\.0/);
  });
});

describe("private contact introductions", () => {
  it("rechecks the same draft internally through sendDraft and chat", async () => {
    const id = "5d79f608-6601-4ef5-aa6c-c50d85c895ea";
    const key = "c5477bd4-1090-4502-8e2a-2d1bb84da56a";
    const states = ["draft", "pending", "pending"];
    const keys = [];
    const op = new AMessage({
      token: "agt_sender",
      fetch: async (url, init) => {
        assert.equal(new URL(url).pathname, "/v1/messages");
        assert.equal(init.method, "POST");
        assert.equal(init.headers.Authorization, "Bearer agt_sender");
        assert.deepEqual(JSON.parse(init.body), { draft_message_id: id });
        keys.push(init.headers["Idempotency-Key"]);
        return Response.json({ id, state: states.shift() }, { status: 200 });
      },
    });
    assert.deepEqual(await op.sendDraft(id), { id, state: "draft" });
    assert.deepEqual(await op.chat({ action: "send_draft", id, key }), { id, state: "pending" });
    assert.deepEqual(await op.sendDraft(id, key), { id, state: "pending" });
    assert.match(keys[0], /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    assert.notEqual(keys[0], key);
    assert.deepEqual(keys.slice(1), [key, key]);
    assert.throws(() => op.sendDraft(""), /requires a resource id/);
  });

  it("resumes an inbox, keeps draft invites explicit and reuses a persisted write key", async () => {
    const calls = [];
    const key = "fcf5d99e-876b-41d8-aebb-ae67e6ad8b92";
    const draft = { id: "m", request_id: "r", state: "draft", invitation_available: true };
    const fetch = async (url, init) => {
      const target = new URL(url);
      calls.push({
        path: target.pathname + target.search,
        headers: init.headers,
        body: init.body && JSON.parse(init.body),
      });
      const data = {
        "/v1/inbox": { cursor: "start/+" },
        "/v1/events": { next_cursor: "resumed", data: [], has_more: false, truncated: false, next_poll_ms: 5000 },
        "/v1/messages": draft,
        "/v1/requests/r/invitation": { state: "invited", invitation: { delivery: "queued" } },
        "/v1/me/addresses": { data: [{ id: "addr", etag: '"opaque"' }], next_cursor: null },
        "/v1/me/addresses/addr": { routing: "invitations_only" },
      }[target.pathname];
      return Response.json(data);
    };
    const op = new AMessage({ fetch, token: "agt_private", saveToken: false });
    const snapshot = await op.inbox();
    const events = await op.events(snapshot.cursor);
    assert.equal(calls.at(-1).path, "/v1/events?cursor=start%2F%2B");
    assert.equal(events.next_cursor, "resumed");
    for (let i = 0; i < 2; i++)
      assert.deepEqual(await op.sendMessage({ phone: "+14155550100" }, "Hello", { key }), draft);
    assert.equal(calls.filter((c) => c.headers["Idempotency-Key"] === key).length, 2);
    assert.equal(calls.length, 4);
    const invited = await op.invite(draft.request_id, "sms", "Morgan");
    assert.equal(invited.invitation.delivery, "queued");
    assert.deepEqual(calls.at(-1).body, { channel: "sms", sender_name: "Morgan" });
    const [address] = (await op.chat({ action: "addresses" })).data;
    await op.chat({ action: "route_address", id: address.id, etag: address.etag, routing: "invitations_only" });
    assert.equal(calls.at(-1).headers["If-Match"], '"opaque"');
    assert.deepEqual(calls.at(-1).body, { routing: "invitations_only" });
  });
});

/**
 * A stand-in for GET and PATCH /v1/me and /v1/me/preferences: keeps one agent's name and
 * inbox settings, answers with an ETag, and refuses a stale If-Match like the API does.
 */
function meApi({ new_contacts = "requests", allow_from = "anyone" } = {}) {
  const calls = [];
  const state = { name: null, prefs: { new_contacts, allow_from }, revision: 1 };
  const me = () => ({ agent_id: "a1", inbox_id: "a1", name: state.name, linked_to_account: false });
  const fetch = async (url, init = {}) => {
    const path = new URL(url).pathname;
    const method = init.method ?? "GET";
    const body = init.body ? JSON.parse(init.body) : undefined;
    calls.push({ method, path, headers: init.headers ?? {}, body });
    if (path === "/v1/me" && method === "GET") return Response.json(me());
    if (path === "/v1/me" && method === "PATCH") {
      state.name = body.name;
      return Response.json(me());
    }
    const tag = { etag: `"${state.revision}"` };
    if (path === "/v1/me/preferences" && method === "GET") return Response.json(state.prefs, { headers: tag });
    if (path === "/v1/me/preferences" && method === "PATCH") {
      if (init.headers["If-Match"] !== tag.etag)
        return Response.json({ code: "stale_version", detail: "It changed." }, { status: 412 });
      state.prefs = { ...state.prefs, ...body };
      state.revision += 1;
      return Response.json(state.prefs, { headers: { etag: `"${state.revision}"` } });
    }
    return Response.json({ code: "not_found", detail: "No such path." }, { status: 404 });
  };
  return { fetch, calls, state };
}

const meClient = (api) => new AMessage({ fetch: api.fetch, token: "agt_me", saveToken: false });
const sent = (api) => api.calls.map((c) => `${c.method} ${c.path}`);

describe("this agent and its inbox settings", () => {
  it("shows its own agent ID and sets or removes the name others see", async () => {
    const api = meApi();
    const op = meClient(api);
    assert.deepEqual(await op.me(), { agent_id: "a1", inbox_id: "a1", name: null, linked_to_account: false });
    assert.equal((await op.setName("Build bot")).name, "Build bot");
    assert.deepEqual(api.calls.at(-1).body, { name: "Build bot" });
    assert.equal(api.calls.at(-1).headers.Authorization, "Bearer agt_me");
    assert.equal((await op.chat({ action: "me" })).name, "Build bot");
    assert.equal((await op.chat({ action: "set_name", name: null })).name, null);
    assert.deepEqual(api.calls.at(-1).body, { name: null });
    assert.deepEqual(sent(api), ["GET /v1/me", "PATCH /v1/me", "GET /v1/me", "PATCH /v1/me"]);
    assert.throws(() => op.setName(undefined), /set_name needs a name/);
    assert.throws(() => op.chat({ action: "set_name" }), TypeError);
    assert.equal(api.calls.length, 4);
  });

  it("reads the preferences with their etag, and setPreferences reads the etag itself when none is given", async () => {
    const api = meApi();
    const op = meClient(api);
    assert.deepEqual(await op.preferences(), { new_contacts: "requests", allow_from: "anyone", etag: '"1"' });
    assert.deepEqual(await op.setPreferences({ allow_from: "phone" }), {
      new_contacts: "requests",
      allow_from: "phone",
    });
    assert.deepEqual(sent(api).slice(1), ["GET /v1/me/preferences", "PATCH /v1/me/preferences"]);
    assert.equal(api.calls.at(-1).headers["If-Match"], '"1"');
    assert.deepEqual(api.calls.at(-1).body, { allow_from: "phone" });
    await op.setPreferences({ new_contacts: "open", allow_from: "phone_or_email", etag: '"2"' });
    assert.equal(api.calls.at(-2).method, "PATCH", "a given etag is used without reading again");
    assert.deepEqual(api.calls.at(-1).body, { new_contacts: "open", allow_from: "phone_or_email" });
    await assert.rejects(op.setPreferences({ allow_from: "email", etag: '"1"' }), { status: 412, code: "stale_version" });
    const calls = api.calls.length;
    await assert.rejects(op.setPreferences({}), /new_contacts, allow_from or both/);
    assert.equal(api.calls.length, calls);
  });

  it("chats preferences and set_preferences as the CLI does, with the etag the model copies", async () => {
    const api = meApi();
    const op = meClient(api);
    const current = await op.chat({ action: "preferences" });
    assert.deepEqual(current, { new_contacts: "requests", allow_from: "anyone", etag: '"1"' });
    const changed = await op.chat({ action: "set_preferences", new_contacts: "closed", etag: current.etag });
    assert.equal(changed.new_contacts, "closed");
    assert.deepEqual(api.calls.at(-1).body, { new_contacts: "closed" });
    assert.equal(api.calls.at(-1).headers["If-Match"], '"1"');
    assert.throws(() => op.chat({ action: "set_preferences", allow_from: "phone" }), /ETag returned by the preferences/);
  });

  it("setTakingMessages keeps an open inbox open, asks first otherwise, and closes it", async () => {
    const open = meApi({ new_contacts: "open" });
    assert.equal((await meClient(open).setTakingMessages(true)).new_contacts, "open");
    assert.deepEqual(open.calls.at(-1).body, { new_contacts: "open" });
    const closed = meApi({ new_contacts: "closed" });
    assert.equal((await meClient(closed).setTakingMessages(true, '"1"')).new_contacts, "requests");
    assert.equal(closed.calls.at(-1).headers["If-Match"], '"1"');
    const api = meApi({ new_contacts: "open", allow_from: "phone" });
    const op = meClient(api);
    assert.deepEqual(await op.setTakingMessages(false), { new_contacts: "closed", allow_from: "phone" });
    assert.deepEqual(sent(api), ["GET /v1/me/preferences", "PATCH /v1/me/preferences"]);
    await op.setTakingMessages(false, '"2"');
    assert.deepEqual(sent(api).slice(2), ["PATCH /v1/me/preferences"], "closing with an etag reads nothing");
  });
});
