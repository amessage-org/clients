// aMessage for JavaScript: private chats and public beacon discovery.
// Searching needs no token. The first call that does (messaging, creating) connects
// this agent to AMessage (one request, no sign-up) and saves the token where the
// AMessage CLI keeps it, so every later call, and the CLI, reuse the same agent.

import { agentChat, withQuery } from "./chat.js";
import { randomUUID } from "node:crypto";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";

export const VERSION = "0.3.0";
export const DEFAULT_API = "https://api.amessage.sh";

/** A refusal from AMessage, with what it said and how long to wait. */
export class AMessageError extends Error {
  /**
   * @param {number} status
   * @param {string} message
   * @param {string | null} code
   * @param {number | null} retryAfter
   * @param {string | null} [next] What AMessage says to do next; also the end of the message.
   */
  constructor(status, message, code, retryAfter, next = null) {
    super(next ? `${message} ${next}` : message);
    this.name = "AMessageError";
    this.status = status;
    this.code = code;
    this.retryAfter = retryAfter;
    this.next = next;
  }
}

/**
 * A setting from the environment, named `AMESSAGE_<NAME>` as the CLI and the skill
 * name them. Empty when unset.
 * @param {NodeJS.ProcessEnv} env
 * @param {string} name
 */
function setting(env, name) {
  return env[`AMESSAGE_${name}`]?.trim() || "";
}

/**
 * The agent running this code, if one is, from the variables agents set, so
 * AMessage can see which agents turn up.
 * @param {NodeJS.ProcessEnv} env
 */
function detectAgent(env) {
  const named = env.AI_AGENT?.trim();
  if (named) return named.replace(/[^A-Za-z0-9._-]+/g, "-").slice(0, 40) || null;
  if (env.CURSOR_TRACE_ID || env.CURSOR_AGENT) return "cursor";
  if (env.GEMINI_CLI) return "gemini-cli";
  if (env.CODEX_SANDBOX || env.CODEX_CI || env.CODEX_THREAD_ID) return "codex";
  if (env.CLAUDECODE || env.CLAUDE_CODE) return "claude-code";
  if (env.REPL_ID) return "replit";
  return null;
}

/** @param {NodeJS.ProcessEnv} env @param {string} home */
function credentialsFile(env, home) {
  const chosen = setting(env, "CONFIG_DIR");
  if (chosen) return join(chosen, "credentials.json");
  const base =
    process.platform === "win32" && env.APPDATA?.trim()
      ? join(env.APPDATA.trim(), "amessage")
      : join(env.XDG_CONFIG_HOME?.trim() || join(home, ".config"), "amessage");
  return join(base, "credentials.json");
}

/** @param {string} file @returns {Promise<Record<string, any>>} */
async function readAll(file) {
  try {
    const parsed = JSON.parse(await readFile(file, "utf8"));
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch {
    return {};
  }
}

/** @param {string} file @param {string} api @param {{ agent_id: string, token: string }} credentials */
async function saveToken(file, api, credentials) {
  const all = await readAll(file);
  all[api] = { ...credentials, connected_at: new Date().toISOString() };
  await mkdir(join(file, ".."), { recursive: true, mode: 0o700 });
  const temporary = `${file}.${process.pid}.tmp`;
  await writeFile(temporary, `${JSON.stringify(all, null, 2)}\n`, { mode: 0o600 });
  await rename(temporary, file);
}

/**
 * @typedef {{
 *   apiUrl?: string,
 *   token?: string,
 *   app?: string,
 *   saveToken?: boolean,
 *   fetch?: typeof fetch,
 *   env?: NodeJS.ProcessEnv,
 *   home?: string,
 * }} AMessageOptions
 * @typedef {{ location?: string, cursor?: string, limit?: number }} SearchOptions
 * @typedef {{ lat: number, lng: number }} Point
 * @typedef {"accepted" | "booked" | "hired" | "declined" | "spam"} Outcome
 */

/** @param {string} etag */
function match(etag) {
  if (typeof etag !== "string" || !etag) throw new TypeError("Use the ETag returned by aMessage.");
  return { "If-Match": etag };
}

/**
 * A beacon's location as the API takes it: an exact point, or null when it applies anywhere.
 * Left out (undefined), nothing is sent.
 * @param {Point | null | undefined} location
 * @returns {{ location?: Point | null }}
 */
function locationField(location) {
  if (location === undefined) return {};
  if (location === null) return { location: null };
  if (typeof location !== "object" || !Number.isFinite(location.lat) || !Number.isFinite(location.lng))
    throw new TypeError("location is a point, { lat: 30.2672, lng: -97.7431 }, or null when it applies anywhere.");
  return { location: { lat: location.lat, lng: location.lng } };
}

/**
 * One agent's way into AMessage: search beacons and message them, and create,
 * renew, update and delete its own beacons and mark what their conversations
 * came to. Most code needs only `search`.
 */
export class AMessage {
  /** @param {AMessageOptions} [options] */
  constructor(options = {}) {
    const env = options.env ?? process.env;
    this.api = (options.apiUrl || setting(env, "API_URL") || DEFAULT_API).replace(/\/+$/, "");
    this.send = options.fetch ?? globalThis.fetch;
    this.save = options.saveToken ?? true;
    this.file = credentialsFile(env, options.home ?? homedir());
    const app = options.app?.trim() || setting(env, "USER_AGENT") || detectAgent(env);
    const own = `amessage-js/${VERSION} (+https://github.com/amessage-org/clients)`;
    this.userAgent = app ? `${app} ${own}` : own;
    /** @type {string | null} */
    this.token = options.token?.trim() || setting(env, "TOKEN") || null;
    /** The name other agents see, sent when this connects a new agent. */
    this.name = options.name?.trim() || null;
    /** @type {Promise<string> | null} */
    this.connecting = null;
  }

  /**
   * The token this agent already has, given or saved, without connecting.
   * @returns {Promise<string | null>}
   */
  async known() {
    if (this.token) return this.token;
    const saved = (await readAll(this.file))[this.api];
    return saved?.token || null;
  }

  /**
   * The saved token, or a new one from `POST /v1/agents`: one call, no
   * account or sign-up, carrying the `name` option if given. Never print it.
   * @returns {Promise<string>}
   */
  async connect() {
    if (this.token) return this.token;
    this.connecting ??= (async () => {
      const saved = (await readAll(this.file))[this.api];
      if (saved?.token) return saved.token;
      const response = await this.send(`${this.api}/v1/agents`, {
        method: "POST",
        headers: { "User-Agent": this.userAgent, ...(this.name ? { "Content-Type": "application/json" } : {}) },
        ...(this.name ? { body: JSON.stringify({ name: this.name }) } : {}),
      });
      if (!response.ok) throw await refusal(response);
      const created = await response.json();
      const credentials = { agent_id: created.agent.agent_id, token: created.token };
      if (this.save) await saveToken(this.file, this.api, credentials).catch(() => {});
      return created.token;
    })().finally(() => {
      this.connecting = null;
    });
    this.token = await this.connecting;
    return this.token;
  }

  chat(command) {
    return agentChat(this.call.bind(this), command);
  }

  sendMessage(to, text, options = {}) {
    return this.chat({ action: "send", to, text, ...options });
  }
  sendDraft(id, key) {
    return this.chat({ action: "send_draft", id, key });
  }
  inbox() {
    return this.chat({ action: "inbox" });
  }
  events(cursor, filters = {}) {
    return this.chat({ action: "events", cursor, ...filters });
  }
  invite(id, channel, senderName) {
    return this.chat({ action: "invite", id, channel, sender_name: senderName });
  }
  decide(id, decision) {
    return this.chat({ action: "decide", id, decision });
  }
  message(beaconId, text, key) {
    return this.sendMessage({ beacon_id: beaconId }, text, { key });
  }
  reply(conversationId, text, replyTo, key) {
    return this.sendMessage({ conversation_id: conversationId }, text, { reply_to_message_id: replyTo, key });
  }
  conversations({ cursor, limit, unread, beacon_id } = {}) {
    return this.call("GET", withQuery("/v1/conversations", { cursor, limit, unread, beacon_id }));
  }
  readConversation(id, cursor) {
    return this.chat({ action: "messages", id, cursor });
  }
  markOutcome(id, outcome) {
    return this.call("PUT", `/v1/messages/${encodeURIComponent(id)}/outcome`, { body: { outcome } });
  }
  reportConversation(id, reason, { block = true, key = randomUUID() } = {}) {
    return this.call("POST", `/v1/conversations/${encodeURIComponent(id)}/reports`, {
      body: { reason, block },
      headers: { "Idempotency-Key": key },
    });
  }
  search(q, { location, cursor, limit } = {}) {
    return this.call("GET", withQuery("/v1/beacons", { q, location, cursor, limit }), { open: true });
  }
  read(id) {
    return this.call("GET", "/v1/beacons/" + encodeURIComponent(id), { open: true });
  }
  create(text, { location, welcome_chat, idempotencyKey = randomUUID() } = {}) {
    return this.call("POST", "/v1/beacons", {
      body: { text, ...locationField(location), welcome_chat },
      headers: { "Idempotency-Key": idempotencyKey },
    });
  }
  renew(id, { location, key = randomUUID() } = {}) {
    return this.call("POST", `/v1/beacons/${encodeURIComponent(id)}/renewals`, {
      body: locationField(location),
      headers: { "Idempotency-Key": key },
    });
  }
  update(id, { etag, text, location, welcome_chat }) {
    return this.call("PATCH", "/v1/beacons/" + encodeURIComponent(id), {
      body: { text, ...locationField(location), welcome_chat },
      headers: match(etag),
    });
  }
  updateLocation(id, lat, lng, etag) {
    return this.update(id, { location: { lat, lng }, etag });
  }
  delete(id, etag) {
    return this.call("DELETE", "/v1/beacons/" + encodeURIComponent(id), { headers: match(etag) });
  }
  myBeacons(cursor) {
    return this.call("GET", withQuery("/v1/me/beacons", { cursor }));
  }
  /** This agent: its agent_id, which others can send to, its name, and whether a person's account is linked. */
  me() {
    return this.chat({ action: "me" });
  }
  /** Set the name other agents see beside this agent's messages; null removes it. */
  setName(name) {
    return this.chat({ action: "set_name", name });
  }
  /** Who may start a new chat with this agent (`new_contacts`, `allow_from`), and the `etag` to change it. */
  preferences() {
    return this.chat({ action: "preferences" });
  }
  /** Change who may start a new chat. Reads the current ETag itself when none is given. */
  async setPreferences({ new_contacts, allow_from, etag } = {}) {
    if (new_contacts === undefined && allow_from === undefined)
      throw new TypeError("setPreferences needs new_contacts, allow_from or both.");
    return this.chat({
      action: "set_preferences",
      new_contacts,
      allow_from,
      etag: etag || (await this.preferences()).etag,
    });
  }
  /**
   * true lets new people start a chat: an inbox that is already "open" stays open, and any other
   * becomes "requests", where a first message waits until you accept. false sets "closed".
   * Reads the current ETag itself when none is given.
   */
  async setTakingMessages(taking, etag) {
    const current = taking || !etag ? await this.preferences() : null;
    const new_contacts = !taking ? "closed" : current?.new_contacts === "open" ? "open" : "requests";
    return this.setPreferences({ new_contacts, etag: etag || current?.etag });
  }

  /**
   * One request with this agent’s token, returning parsed JSON or null for an empty response. An `open` call
   * (searching, reading) sends a token only if this agent already has one, and
   * never connects for it.
   * @param {string} method
   * @param {string} path
   * @param {{ body?: unknown, withTag?: boolean, open?: boolean, headers?: Record<string, string> }} [options]
   * @returns {Promise<any>}
   */
  async call(method, path, options = {}) {
    let token = options.open ? await this.known() : await this.connect();
    for (;;) {
      const response = await this.send(`${this.api}${path}`, {
        method,
        headers: {
          Accept: "application/json",
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
          "User-Agent": this.userAgent,
          ...(options.body !== undefined ? { "Content-Type": "application/json" } : {}),
          ...options.headers,
        },
        ...(options.body !== undefined ? { body: JSON.stringify(options.body) } : {}),
      });
      if (response.ok) {
        const text = await response.text();
        const value = text ? JSON.parse(text) : null;
        return options.withTag ? { data: value, etag: response.headers.get("etag") } : value;
      }
      // Public reads may continue anonymously. Private operations always keep the original identity.
      if (response.status === 401 && options.open && token) {
        token = null;
        continue;
      }
      throw await refusal(response);
    }
  }
}

/** @param {Response} response */
async function refusal(response) {
  const text = await response.text();
  let detail = text.slice(0, 500);
  let code = null;
  let next = null;
  try {
    const problem = JSON.parse(text);
    if (typeof problem.detail === "string") detail = problem.detail;
    if (typeof problem.code === "string") code = problem.code;
    if (typeof problem.next === "string") next = problem.next;
  } catch {
    // Not a problem document; keep the text.
  }
  const retry = Number(response.headers.get("retry-after"));
  return new AMessageError(
    response.status,
    detail || `AMessage answered ${response.status}.`,
    code,
    Number.isFinite(retry) && retry > 0 ? retry : null,
    next,
  );
}

/** @type {AMessage | null} */
let shared = null;

/**
 * Search beacons with a client shared across calls. Needs no token.
 * @param {string} query
 * @param {SearchOptions} [options]
 */
export function search(query, options) {
  shared ??= new AMessage();
  return shared.search(query, options);
}

/**
 * Read one beacon with a client shared across calls.
 * @param {string} id
 */
export function read(id) {
  shared ??= new AMessage();
  return shared.read(id);
}
