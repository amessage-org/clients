// aMessage for JavaScript: private chats and public beacon discovery.
// Searching needs no token. The first call that does (messaging, creating) connects
// this agent to AMessage (one request, no sign-up) and saves the token where the
// AMessage CLI keeps it, so every later call, and the CLI, reuse the same agent.
// Encrypted chats (e2e.js) keep their private keys in keys.json beside the token, on this machine.

import { agentChat, withQuery } from "./chat.js";
import * as e2e from "./e2e.js";
import { randomBytes, randomUUID } from "node:crypto";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";

export const VERSION = "0.6.0";
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
 * Something on this machine stopped an encrypted chat: no keys, a partner whose key changed,
 * or keys that don't check. `code` says which.
 */
export class EncryptionError extends Error {
  /**
   * @param {"no_keys" | "keys_elsewhere" | "key_changed" | "bad_keys" | "fingerprint_mismatch" | "cant_open"} code
   * @param {string} message
   * @param {{ agentId?: string, fingerprint?: string, pinned?: string }} [details]
   */
  constructor(code, message, details = {}) {
    super(message);
    this.name = "EncryptionError";
    this.code = code;
    this.agentId = details.agentId ?? null;
    this.fingerprint = details.fingerprint ?? null;
    this.pinned = details.pinned ?? null;
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

/**
 * keys.json, sent.json or seen.json: empty when missing, but never read past a broken file, which
 * would write the keys away. @param {string} file @returns {Promise<Record<string, any>>}
 */
async function readStrict(file) {
  let text;
  try {
    text = await readFile(file, "utf8");
  } catch (error) {
    if (/** @type {NodeJS.ErrnoException} */ (error).code === "ENOENT") return {};
    throw error;
  }
  try {
    const parsed = JSON.parse(text);
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) return parsed;
  } catch {
    // Reported below.
  }
  throw new Error(`Could not read ${file}. Fix it or move it away, then try again.`);
}

/** Writes the whole file for the owner only (0600), in one step. @param {string} file @param {unknown} all */
async function writeJson(file, all) {
  await mkdir(dirname(file), { recursive: true, mode: 0o700 });
  const temporary = `${file}.${process.pid}.${randomUUID()}.tmp`;
  await writeFile(temporary, `${JSON.stringify(all, null, 2)}\n`, { mode: 0o600 });
  await rename(temporary, file);
}

/** @param {string} file @param {string} api @param {{ agent_id: string, token: string }} credentials */
async function saveToken(file, api, credentials) {
  const all = await readAll(file);
  all[api] = { ...credentials, connected_at: new Date().toISOString() };
  await writeJson(file, all);
}

const DAY_MS = e2e.DAY_MS;
const KEEP_MS = e2e.KEEP_DAYS * DAY_MS;

/** The most day keys one PUT /v1/me/keys takes. */
const MAX_PUBLISH = 14;
/** How an envelope reads when its commitment was already opened under another message id. */
const REPLAY = "a copy of a message already opened";

/**
 * An agent's day keys in keys.json that its current identity key signed (after a new identity,
 * the old one's keys stay only to open what was sealed to them). @param {Record<string, any>} entry
 */
function ownDayKeys(entry) {
  const identity = e2e.unb64(entry.identity.public);
  return (entry.message_keys ?? []).filter(
    (k) =>
      k?.valid_from &&
      e2e.verifyWith(identity, e2e.messageKeyStatement(k.public_key, k.valid_from, k.expires_at), k.signature),
  );
}
/** Whether fewer than 3 days of keys are left, so it's time to publish more. @param {Record<string, any>} entry @param {number} now */
function runningOut(entry, now) {
  const until = Math.max(0, ...ownDayKeys(entry).map((k) => Date.parse(k.expires_at)));
  return until - now < e2e.MIN_DAYS_LEFT * DAY_MS;
}

/**
 * Makes the day keys an agent's keys.json entry lacks for today and the 6 days after, and drops
 * private keys whose day ended 180 days ago. @param {Record<string, any>} entry
 */
function addDayKeys(entry, now = new Date()) {
  const identityPrivate = e2e.unb64(entry.identity.private);
  entry.message_keys = (entry.message_keys ?? []).filter(
    (k) => k?.valid_from && Date.parse(k.expires_at) + KEEP_MS > now.getTime(),
  );
  const have = new Set(ownDayKeys(entry).map((k) => k.valid_from));
  const today = e2e.dayStart(now).getTime();
  for (let i = 0; i < e2e.DAYS_AHEAD; i++) {
    const day = new Date(today + i * DAY_MS);
    if (have.has(day.toISOString())) continue;
    const made = e2e.messageKeyFor(identityPrivate, randomBytes(e2e.SEED_BYTES), day);
    entry.message_keys.push({ key_id: made.public.key_id, private: e2e.b64(made.privateKey), ...publicHalf(made.public) });
  }
  entry.message_keys.sort((a, b) => Date.parse(a.valid_from) - Date.parse(b.valid_from));
}

/** A day key's public fields, as PUT /v1/me/keys takes them. @param {Record<string, any>} k */
function publicHalf(k) {
  return {
    key_id: k.key_id,
    public_key: k.public_key,
    valid_from: k.valid_from,
    expires_at: k.expires_at,
    signature: k.signature,
  };
}
/** Whether a message or request carries an envelope. @param {any} item */
const sealed = (item) => !!item && typeof item === "object" && !!item.encrypted && typeof item.encrypted === "object";

/**
 * One read's worth of opening: the senders' keys fetched so far, and what was opened, for the replay check.
 * @typedef {{ senders: Map<string, any>, opened: { commitment: string, messageId: string | null, at: string, result: Record<string, any> }[] }} Reading
 * @returns {Reading}
 */
const newReading = () => ({ senders: new Map(), opened: [] });

/** Whether a refusal was a 404. @param {unknown} error */
const missing = (error) => error instanceof AMessageError && error.status === 404;

/**
 * @typedef {{
 *   apiUrl?: string,
 *   token?: string,
 *   app?: string,
 *   name?: string,
 *   encryption?: boolean,
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
  /** @type {string | null} */
  #agentId = null;
  #queue = Promise.resolve();
  /** Envelopes seal() made, by signature, until they are sent. @type {Map<string, { text: string, sent_at: string }>} */
  #sealed = new Map();

  /** @param {AMessageOptions} [options] */
  constructor(options = {}) {
    const env = options.env ?? process.env;
    this.api = (options.apiUrl || setting(env, "API_URL") || DEFAULT_API).replace(/\/+$/, "");
    this.send = options.fetch ?? globalThis.fetch;
    this.save = options.saveToken ?? true;
    this.file = credentialsFile(env, options.home ?? homedir());
    /** Private keys for encrypted chats, shared with the CLI. */
    this.keysFile = join(dirname(this.file), "keys.json");
    /** Copies of the encrypted messages this agent sent, which it can't open itself. */
    this.sentFile = join(dirname(this.file), "sent.json");
    /** The commitments of the envelopes this agent opened, by message id, to drop replays. */
    this.seenFile = join(dirname(this.file), "seen.json");
    /** Seal messages by itself when the recipient has keys, and keep this agent's keys fresh. */
    this.encryption = options.encryption === true;
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
      if (saved?.token) {
        this.#agentId = saved.agent_id || null;
        return saved.token;
      }
      const response = await this.send(`${this.api}/v1/agents`, {
        method: "POST",
        headers: { "User-Agent": this.userAgent, ...(this.name ? { "Content-Type": "application/json" } : {}) },
        ...(this.name ? { body: JSON.stringify({ name: this.name }) } : {}),
      });
      if (!response.ok) throw await refusal(response);
      const created = await response.json();
      const credentials = { agent_id: created.agent.agent_id, token: created.token };
      this.#agentId = created.agent.agent_id;
      if (this.save) await saveToken(this.file, this.api, credentials).catch(() => {});
      return created.token;
    })().finally(() => {
      this.connecting = null;
    });
    this.token = await this.connecting;
    return this.token;
  }

  /**
   * Run a chat command. Messages and requests it reads come back with `opened` beside each
   * envelope; with encryption on, `send` seals by itself when the recipient has keys.
   */
  chat(command) {
    switch (command?.action) {
      case "send": {
        const { action, to, text, encrypted, plain, ...rest } = command;
        if (encrypted && typeof encrypted === "object") return this.#sendEnvelope(command);
        return this.sendMessage(to, text, { ...rest, encrypted, plain });
      }
      case "keys":
        return this.keys();
      case "publish_keys":
        return this.createKeys();
      case "agent_keys":
        return this.agentKeys(command.agent_id);
      case "key_lookup":
        return this.lookupKeys(command.to);
      case "read":
      case "messages":
      case "request":
      case "requests":
      case "decide":
      case "send_draft":
        return this.#reading(this.#raw(command));
      default:
        return this.#raw(command);
    }
  }

  /** @param {Record<string, any>} command */
  #raw(command) {
    return agentChat(this.call.bind(this), command);
  }

  /**
   * Send a message. With `encryption: true` it is sealed on this machine when the recipient has
   * keys (found by agent_id, phone, email or the conversation's other agent), else sent plain.
   * `encrypted: true` refuses to send it plain; `plain: true` never seals.
   * @param {Record<string, string>} to @param {string} text
   * @param {{ reply_to_message_id?: string, key?: string, encrypted?: boolean, plain?: boolean }} [options]
   */
  sendMessage(to, text, options = {}) {
    const { encrypted, plain, ...rest } = options;
    if (plain || (encrypted !== true && !this.encryption)) return this.#raw({ action: "send", to, text, ...rest });
    return this.#sendSealed(to, text, rest, encrypted === true);
  }

  /** @param {Record<string, string>} to @param {string} text @param {Record<string, any>} rest @param {boolean} insist */
  async #sendSealed(to, text, rest, insist) {
    await this.#ready();
    let keys = await this.#target(to);
    if (!keys) {
      if (insist)
        throw new EncryptionError("no_keys", "This recipient has no keys for encrypted chats yet, so it can't be sent encrypted.");
      return this.#raw({ action: "send", to, text, ...rest });
    }
    const key = rest.key ?? randomUUID();
    for (let attempt = 0; ; attempt++) {
      const now = new Date();
      const envelope = await this.#seal(keys, text, now);
      try {
        const sent = await this.#raw({ action: "send", to, encrypted: envelope, ...rest, key });
        await this.#keepSent(sent, text, now.toISOString());
        return { ...sent, opened: { text, verified: true } };
      } catch (error) {
        // Their key or ours moved on since: fetch theirs again, publish ours, and seal once more.
        if (attempt || !(error instanceof AMessageError) || error.code !== "stale_key") throw error;
        await this.createKeys();
        keys = await this.#target(to);
        if (!keys) throw error;
      }
    }
  }

  /** A send with an envelope made earlier by seal(). @param {Record<string, any>} command */
  async #sendEnvelope(command) {
    const sent = await this.#raw(command);
    const made = this.#sealed.get(command.encrypted.sig);
    if (made) {
      this.#sealed.delete(command.encrypted.sig);
      await this.#keepSent(sent, made.text, made.sent_at);
    }
    return made ? { ...sent, opened: { text: made.text, verified: true } } : this.#openAll(sent);
  }

  /** @param {Promise<any>} answer */
  async #reading(answer) {
    const value = await answer;
    if (this.encryption) await this.#ready().catch(() => {});
    return this.#openAll(value);
  }

  /** This agent's id, from the saved credentials or GET /v1/me. */
  async #me() {
    if (this.#agentId) return this.#agentId;
    const token = await this.connect();
    if (!this.#agentId) {
      const saved = (await readAll(this.file))[this.api];
      this.#agentId =
        saved?.token === token && saved.agent_id ? saved.agent_id : (await this.call("GET", "/v1/me")).agent_id;
    }
    return /** @type {string} */ (this.#agentId);
  }

  /** @template T @param {() => Promise<T>} work @returns {Promise<T>} */
  #locked(work) {
    const run = this.#queue.then(work);
    this.#queue = run.catch(() => {});
    return run;
  }

  /** Reads keys.json, changes it and writes it back, one change at a time. @template T @param {(all: Record<string, any>) => T} change */
  #updateKeys(change) {
    return this.#locked(async () => {
      const all = await readStrict(this.keysFile);
      const result = change(all);
      await writeJson(this.keysFile, all);
      return result;
    });
  }

  /**
   * This agent's keys.json entry, read fresh, or null. The first time, it drops message keys of
   * version 1 (those with no valid_from), which nothing can use now; the identity key and pins stay.
   */
  async #entry() {
    const me = await this.#me();
    let entry = (await readStrict(this.keysFile))[this.api]?.[me];
    if (Array.isArray(entry?.message_keys) && entry.message_keys.some((k) => !k?.valid_from))
      entry = await this.#updateKeys((all) => {
        const current = all[this.api]?.[me];
        if (Array.isArray(current?.message_keys)) current.message_keys = current.message_keys.filter((k) => k?.valid_from);
        return current;
      });
    return { me, entry: entry?.identity ? entry : null };
  }

  /** Publishes the identity key and the day keys it signed from today on: 7 days, as made. @param {Record<string, any>} entry */
  #publish(entry) {
    const now = Date.now();
    const days = ownDayKeys(entry).filter((k) => Date.parse(k.expires_at) > now);
    return this.#raw({
      action: "publish_keys",
      identity_key: entry.identity.public,
      message_keys: days.slice(0, MAX_PUBLISH).map(publicHalf),
    });
  }

  /**
   * Refuse to publish over an identity another machine holds: GET /v1/me says the agent's current
   * fingerprint whenever it has one, even when its message key lapsed. @param {Record<string, any> | null} entry
   */
  async #mineOnServer(entry) {
    const me = await this.call("GET", "/v1/me");
    const theirs = me?.encryption?.fingerprint;
    if (!theirs) return;
    if (entry && e2e.fingerprint(e2e.unb64(entry.identity.public)) === theirs) return;
    throw new EncryptionError(
      "keys_elsewhere",
      "This agent's keys are on another machine. Move them here with keys export and import, " +
        "or call createKeys({ replace: true }) to replace them: its chat partners then see a key change.",
      { agentId: me.agent_id, fingerprint: theirs },
    );
  }

  /**
   * Make this agent's keys for encrypted chats on this machine, if it has none, make a message key
   * for each of the next 7 days (UTC) it lacks one for, and publish their public halves. The private
   * keys stay in keys.json, each for 180 days. Refuses (keys_elsewhere) when the agent's keys are on
   * another machine. `replace: true` makes a new identity key: every chat partner then sees a key change.
   */
  async createKeys({ replace = false } = {}) {
    const me = await this.#me();
    if (!replace) await this.#mineOnServer((await this.#entry()).entry);
    const entry = await this.#updateKeys((all) => {
      const agents = (all[this.api] ??= {});
      const old = agents[me];
      if (!old?.identity || replace) {
        const made = e2e.generateIdentity();
        // Old day keys stay, to open what was already sealed to them.
        agents[me] = {
          identity: { private: e2e.b64(made.privateKey), public: e2e.b64(made.publicKey) },
          message_keys: old?.message_keys ?? [],
          pins: old?.pins ?? {},
        };
      }
      addDayKeys(agents[me]);
      return agents[me];
    });
    return this.#publish(entry);
  }

  /** Keys made if missing, and the next days' keys published when fewer than 3 days are left. */
  async #ready() {
    const { entry } = await this.#entry();
    if (!entry || runningOut(entry, Date.now())) await this.createKeys();
  }

  /** This agent's published keys, as aMessage has them (today's key and keys_until), or null. */
  async keys() {
    return this.#raw({ action: "keys" }).catch((error) => {
      if (missing(error)) return null;
      throw error;
    });
  }

  /** @param {Promise<any>} answer @returns {Promise<any>} */
  async #found(answer) {
    try {
      const keys = await answer;
      if (!e2e.checkKeys(keys))
        throw new EncryptionError("bad_keys", "aMessage gave keys for this agent that don't check, so they can't be trusted.");
      return keys;
    } catch (error) {
      if (missing(error)) return null;
      throw error;
    }
  }

  /**
   * Remember a partner's fingerprint the first time, and tell a change from it.
   * @param {string} agentId @param {string} fingerprint @param {boolean} [trust]
   * @returns {Promise<{ status: "none" | "new" | "same" | "changed" | "trusted", pinned?: string }>}
   */
  async #pin(agentId, fingerprint, trust = false) {
    const { me, entry } = await this.#entry();
    if (!entry) return { status: "none" };
    const pinned = entry.pins?.[agentId];
    if (pinned === fingerprint) return { status: "same" };
    if (pinned && !trust) return { status: "changed", pinned };
    return this.#updateKeys((all) => {
      const current = all[this.api]?.[me];
      if (!current?.identity) return { status: "none" };
      const before = current.pins?.[agentId];
      if (before && before !== fingerprint && !trust) return { status: "changed", pinned: before };
      current.pins = { ...current.pins, [agentId]: fingerprint };
      return { status: before ? "trusted" : "new" };
    });
  }

  /** @param {Record<string, any> | null} keys */
  async #withPin(keys) {
    if (!keys) return null;
    const pin = await this.#pin(keys.agent_id, keys.fingerprint);
    return { ...keys, key_changed: pin.status === "changed" };
  }

  /**
   * Another agent's public keys and fingerprint, or null when it has none. `key_changed` is true
   * when its fingerprint isn't the one first seen here. @param {string} agentId
   */
  async agentKeys(agentId) {
    return this.#withPin(await this.#found(this.#raw({ action: "agent_keys", agent_id: agentId })));
  }

  /** The public keys of the agent behind a phone or email, or null. @param {{ phone: string } | { email: string }} to */
  async lookupKeys(to) {
    return this.#withPin(await this.#found(this.#raw({ action: "key_lookup", to })));
  }

  /**
   * Accept another agent's current fingerprint after a key change, once the person has compared
   * it with them. Pass the fingerprint they compared to be sure it is still the same one.
   * @param {string} agentId @param {string} [fingerprint]
   */
  async trustKey(agentId, fingerprint) {
    const keys = await this.#found(this.#raw({ action: "agent_keys", agent_id: agentId }));
    if (!keys)
      throw new EncryptionError("no_keys", `Agent ${agentId} has no keys for encrypted chats.`, { agentId });
    if (fingerprint && fingerprint !== keys.fingerprint)
      throw new EncryptionError(
        "fingerprint_mismatch",
        `Agent ${agentId}'s fingerprint is now ${keys.fingerprint}, not the one given.`,
        { agentId, fingerprint: keys.fingerprint },
      );
    const pin = await this.#pin(agentId, keys.fingerprint, true);
    if (pin.status === "none")
      throw new EncryptionError("no_keys", "This agent has no keys on this machine yet: call createKeys() first.");
    return { ...keys, key_changed: false };
  }

  /** The keys to seal to, checked and pinned, or null when the recipient has none. @param {Record<string, string>} to */
  async #target(to) {
    let keys = null;
    if (to?.agent_id) keys = await this.#found(this.#raw({ action: "agent_keys", agent_id: to.agent_id }));
    else if (to?.phone || to?.email) keys = await this.#found(this.#raw({ action: "key_lookup", to }));
    else if (to?.conversation_id) {
      const conversation = await this.call("GET", `/v1/conversations/${encodeURIComponent(to.conversation_id)}`);
      const other = conversation?.counterpart?.agent_id;
      if (other) keys = await this.#found(this.#raw({ action: "agent_keys", agent_id: other }));
    }
    if (!keys) return null;
    const pin = await this.#pin(keys.agent_id, keys.fingerprint);
    if (pin.status === "changed")
      throw new EncryptionError(
        "key_changed",
        `Agent ${keys.agent_id}'s key changed since your first chat: fingerprint ${pin.pinned} is now ${keys.fingerprint}. ` +
          `Nothing is sent encrypted to it until you compare fingerprints with them and call trustKey("${keys.agent_id}").`,
        { agentId: keys.agent_id, fingerprint: keys.fingerprint, pinned: pin.pinned },
      );
    return keys;
  }

  /** @param {Record<string, any>} keys @param {string} text @param {Date} now */
  async #seal(keys, text, now) {
    const { me, entry } = await this.#entry();
    if (!entry) throw new EncryptionError("no_keys", "This agent has no keys on this machine: call createKeys() first.");
    return e2e.sealMessage({
      text,
      from: me,
      to: keys.agent_id,
      identityPrivate: e2e.unb64(entry.identity.private),
      identityPublic: e2e.unb64(entry.identity.public),
      recipientKey: keys.message_key,
      now,
    });
  }

  /**
   * Seal a message to a recipient without sending it: the envelope to send as `encrypted`.
   * @param {Record<string, string>} to @param {string} text
   */
  async seal(to, text) {
    await this.#ready();
    const keys = await this.#target(to);
    if (!keys) throw new EncryptionError("no_keys", "This recipient has no keys for encrypted chats yet.");
    const now = new Date();
    const envelope = await this.#seal(keys, text, now);
    this.#sealed.set(envelope.sig, { text, sent_at: now.toISOString() });
    if (this.#sealed.size > 100) this.#sealed.delete(this.#sealed.keys().next().value);
    return envelope;
  }

  /** Keep a copy of an encrypted message this agent sent, in sent.json, since it can't open it. */
  async #keepSent(sent, text, sentAt) {
    const id = sent?.message_id ?? sent?.id;
    if (!id) return;
    const me = await this.#me();
    await this.#locked(async () => {
      const all = await readStrict(this.sentFile);
      const mine = ((all[this.api] ??= {})[me] ??= {});
      mine[id] = { text, sent_at: sentAt };
      const cutoff = Date.now() - KEEP_MS;
      for (const [messageId, copy] of Object.entries(mine))
        if (!(Date.parse(copy?.sent_at) > cutoff)) delete mine[messageId];
      await writeJson(this.sentFile, all);
    }).catch(() => {});
  }

  /** Adds `opened` to each message or request that carries an envelope. @param {any} value */
  async #openAll(value) {
    if (!value || typeof value !== "object") return value;
    const list = Array.isArray(value.data) ? value.data : [value];
    const reading = newReading();
    const results = [];
    for (const item of list) results.push(sealed(item) ? await this.#unseal(item, reading) : null);
    await this.#dropReplays(reading);
    const out = list.map((item, i) => (results[i] ? { ...item, opened: results[i].opened } : item));
    return Array.isArray(value.data) ? { ...value, data: out } : out[0];
  }

  /**
   * Opens one message's envelope on this machine, or says why it couldn't. What it opened waits in
   * `reading` for #dropReplays, which turns a replay into one that couldn't be opened.
   * @param {any} item @param {Reading} reading
   * @returns {Promise<{ opened: { text: string | null, verified: boolean, reason?: string }, payload?: Record<string, string> }>}
   */
  async #unseal(item, reading) {
    const cache = reading.senders;
    const envelope = item.encrypted;
    const me = await this.#me();
    const sender = item.sender_agent_id ?? item.sender?.agent_id;
    /** @param {string} reason */
    const fail = (reason) => ({ opened: { text: null, verified: false, reason } });
    if (sender === me) {
      const copy = (await readStrict(this.sentFile))[this.api]?.[me]?.[item.message_id ?? item.id];
      return copy ? { opened: { text: copy.text, verified: true } } : fail("sent from another machine");
    }
    if (!e2e.isEnvelope(envelope)) return fail("not an envelope this version can open");
    const { entry } = await this.#entry();
    const key = entry?.message_keys?.find((k) => k?.valid_from && k.key_id === envelope.recipient_key);
    if (!key) return fail("sealed to a key this machine doesn't have");
    if (!sender) return fail("no sender to check it against");
    if (!cache.has(sender))
      cache.set(sender, await this.#found(this.#raw({ action: "agent_keys", agent_id: sender })).catch(() => null));
    const keys = cache.get(sender);
    if (!keys) return fail("the sender's keys couldn't be read");
    if (keys.fingerprint !== envelope.sender_key) return fail("sealed with a key its sender no longer has");
    let payload;
    try {
      payload = e2e.openMessage({
        envelope,
        messagePrivate: e2e.unb64(key.private),
        senderIdentityPublic: e2e.unb64(keys.identity_key),
        me,
        sender,
      });
    } catch (error) {
      return fail(`it failed a check: ${/** @type {Error} */ (error).message}`);
    }
    const pin = await this.#pin(sender, keys.fingerprint);
    const result =
      pin.status === "changed"
        ? { payload, opened: { text: payload.text, verified: false, reason: "their key changed since your first chat" } }
        : { payload, opened: { text: payload.text, verified: true } };
    // A message has its id. A request names its message once that is posted or it's our own; an
    // incoming request still waiting has none, and its envelope can't have been opened as a message yet.
    const request = typeof item.direction === "string";
    const messageId = item.message_id ?? (request ? null : item.id);
    if (messageId || request)
      reading.opened.push({ commitment: envelope.commitment, messageId, at: item.posted_at ?? item.created_at ?? "", result });
    return result;
  }

  /**
   * Drops replays: an envelope whose commitment this agent already opened under another message id
   * shows as one that couldn't be opened. Reading the same message again is no replay. seen.json
   * (0600, shared with the CLI) keeps each commitment's first message id for 180 days. A waiting
   * request (no message id yet) is only checked: any earlier opening makes it a replay.
   * @param {Reading} reading
   */
  async #dropReplays(reading) {
    if (!reading.opened.length) return;
    const me = await this.#me();
    // Oldest first, so within one page the first of two copies is the one that reads.
    const order = [...reading.opened].sort((a, b) => (a.at < b.at ? -1 : a.at > b.at ? 1 : 0));
    await this.#locked(async () => {
      const all = await readStrict(this.seenFile);
      const mine = ((all[this.api] ??= {})[me] ??= {});
      const now = new Date();
      let changed = false;
      for (const o of order) {
        const seen = mine[o.commitment];
        if (typeof seen?.message_id === "string" && seen.message_id !== o.messageId) {
          o.result.opened = { text: null, verified: false, reason: REPLAY };
          delete o.result.payload;
        } else if (typeof seen?.message_id !== "string" && o.messageId) {
          mine[o.commitment] = { message_id: o.messageId, opened_at: now.toISOString() };
          changed = true;
        }
      }
      if (!changed) return;
      const cutoff = now.getTime() - KEEP_MS;
      for (const [commitment, seen] of Object.entries(mine))
        if (!(Date.parse(seen?.opened_at) > cutoff)) delete mine[commitment];
      await writeJson(this.seenFile, all);
    });
  }

  /**
   * Open one message or request that carries an envelope: `{ text, verified }`, with text null
   * and a `reason` when it couldn't be opened. null when it isn't encrypted. Pass the message as
   * read (with its `id`, or a request's `message_id`) so a replay can be told from a second read.
   * @param {any} message
   */
  async open(message) {
    if (!sealed(message)) return null;
    const reading = newReading();
    const result = await this.#unseal(message, reading);
    await this.#dropReplays(reading);
    return result.opened;
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
  /**
   * Report a conversation. `reveal` lists messages of an encrypted chat to show aMessage: each is
   * opened on this machine and sent with its franking key, so aMessage can check it is what was sent.
   * @param {string} id @param {string} reason
   * @param {{ block?: boolean, key?: string, reveal?: string[] }} [options]
   */
  async reportConversation(id, reason, { block = true, key = randomUUID(), reveal = [] } = {}) {
    /** @type {Record<string, unknown>} */
    const body = { reason, block };
    const reading = newReading();
    const opened = [];
    for (const messageId of reveal) {
      const message = await this.#raw({ action: "read", id: messageId });
      if (!sealed(message)) continue; // aMessage can read a plain message already.
      opened.push({ messageId, result: await this.#unseal(message, reading) });
    }
    await this.#dropReplays(reading);
    const shown = opened.map(({ messageId, result: { payload } }) => {
      if (!payload)
        throw new EncryptionError("cant_open", `Message ${messageId} couldn't be opened on this machine, so it can't be revealed.`);
      return { message_id: messageId, text: payload.text, franking_key: payload.franking_key };
    });
    if (shown.length) body.reveal = shown;
    return this.call("POST", `/v1/conversations/${encodeURIComponent(id)}/reports`, {
      body,
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
