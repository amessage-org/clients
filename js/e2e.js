// aMessage's encrypted chats, version 2, on node:crypto alone (Node 24.7 or later): a port of the
// reference (packages/core/src/e2e in the aMessage repo; docs/design/encrypted-chats.md says it in
// words, with test vectors). An agent has an Ed25519 identity key and a message key for each UTC
// day, which the identity key signs. A message is HPKE-sealed (RFC 9180) to the recipient's key for
// the day with a post-quantum hybrid KEM (ML-KEM-768 + X25519, X-Wing) and signed by the sender.
// Private keys stay on this machine: nothing here sends anything anywhere.

import * as nodeCrypto from "node:crypto";
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  randomBytes,
  scryptSync,
  sign as edSign,
  timingSafeEqual,
  verify as edVerify,
} from "node:crypto";

export const SUITE = "mlkem768x25519-hkdf-sha256-chacha20poly1305";
export const VERSION = 2;
const INFO = Buffer.from("amessage e2e v2");
/** The most an envelope may weigh, as JSON: room for 2,000 characters in any script. */
export const MAX_ENVELOPE_BYTES = 14336;
/** The most characters a message's text may have. */
export const MAX_TEXT = 2000;
export const DAY_MS = 86_400_000;
/** Each message key covers one UTC day; clients publish this many days at a time. */
export const DAYS_AHEAD = 7;
/** Clients publish again when fewer than this many days of keys are left. */
export const MIN_DAYS_LEFT = 3;
/** How long private message keys (and copies of sent messages, and opened commitments) are kept. */
export const KEEP_DAYS = 180;

// HPKE (RFC 9180), base mode, single-shot, with one suite from draft-ietf-hpke-pq: MLKEM768-X25519
// (X-Wing), HKDF-SHA256 and ChaCha20-Poly1305 (kem 0x647a, kdf 0x0001, aead 0x0003). The draft's
// appendix A.5 vector checks this code (test/e2e.test.js).

const KEM_ID = 0x647a;
const KDF_ID = 0x0001;
const AEAD_ID = 0x0003;
const NH = 32; // HKDF-SHA256 output
const NK = 32; // ChaCha20-Poly1305 key
const NN = 12; // ChaCha20-Poly1305 nonce
const NT = 16; // Poly1305 tag
/** A message key's private seed, its public key and an encapsulated key, in bytes. */
export const SEED_BYTES = 32;
export const PUBLIC_BYTES = 1216;
export const ENC_BYTES = 1120;
const MLKEM_PUBLIC = 1184;
const MLKEM_CT = 1088;
/** X-Wing's fixed label, "\.//^\". */
const XWING_LABEL = Buffer.from("5c2e2f2f5e5c", "hex");

/** @param {number} n @param {number} w */
const i2osp = (n, w) => {
  const out = Buffer.alloc(w);
  out.writeUIntBE(n, 0, w);
  return out;
};
const EMPTY = Buffer.alloc(0);
const HPKE_SUITE = Buffer.concat([Buffer.from("HPKE"), i2osp(KEM_ID, 2), i2osp(KDF_ID, 2), i2osp(AEAD_ID, 2)]);
const V1 = Buffer.from("HPKE-v1");

/** @param {Buffer} salt @param {Buffer} ikm */
function extract(salt, ikm) {
  return createHmac("sha256", salt.length ? salt : Buffer.alloc(NH)).update(ikm).digest();
}
/** @param {Buffer} prk @param {Buffer} info @param {number} length */
function expand(prk, info, length) {
  const out = [];
  let t = EMPTY;
  for (let i = 1; out.length * NH < length; i++) {
    t = createHmac("sha256", prk).update(Buffer.concat([t, info, Buffer.from([i])])).digest();
    out.push(t);
  }
  return Buffer.concat(out).subarray(0, length);
}
/** @param {Buffer} salt @param {string} label @param {Buffer} ikm */
const labeledExtract = (salt, label, ikm) => extract(salt, Buffer.concat([V1, HPKE_SUITE, Buffer.from(label), ikm]));
/** @param {Buffer} prk @param {string} label @param {Buffer} info @param {number} length */
const labeledExpand = (prk, label, info, length) =>
  expand(prk, Buffer.concat([i2osp(length, 2), V1, HPKE_SUITE, Buffer.from(label), info]), length);

// Raw 32-byte keys as KeyObjects, through their fixed DER prefixes.
const X25519_PKCS8 = Buffer.from("302e020100300506032b656e04220420", "hex");
const X25519_SPKI = Buffer.from("302a300506032b656e032100", "hex");
const ED_PKCS8 = Buffer.from("302e020100300506032b657004220420", "hex");
const ED_SPKI = Buffer.from("302a300506032b6570032100", "hex");
/** @param {Buffer} prefix @param {Buffer} raw */
const privateKey = (prefix, raw) =>
  createPrivateKey({ key: Buffer.concat([prefix, raw]), format: "der", type: "pkcs8" });
/** @param {Buffer} prefix @param {Buffer} raw */
const publicKey = (prefix, raw) => createPublicKey({ key: Buffer.concat([prefix, raw]), format: "der", type: "spki" });
/** @param {import("node:crypto").KeyObject} key */
const rawPublic = (key) => Buffer.from(key.export({ format: "der", type: "spki" })).subarray(12);
/** @param {import("node:crypto").KeyObject} key */
const rawPrivate = (key) => Buffer.from(key.export({ format: "der", type: "pkcs8" })).subarray(16);
/** @param {Buffer} privateRaw @param {Buffer} publicRaw */
const x25519 = (privateRaw, publicRaw) =>
  diffieHellman({ privateKey: privateKey(X25519_PKCS8, privateRaw), publicKey: publicKey(X25519_SPKI, publicRaw) });

/** @typedef {{ privateKey: Buffer, publicKey: Buffer }} KeyPair */

/**
 * Node's ML-KEM, read when first needed, so the rest of the SDK still loads on an older Node.
 * @returns {{ encapsulate: (key: import("node:crypto").KeyObject) => { sharedKey: Buffer, ciphertext: Buffer }, decapsulate: (key: import("node:crypto").KeyObject, ciphertext: Buffer) => Buffer }}
 */
function kem() {
  const { encapsulate, decapsulate } = /** @type {any} */ (nodeCrypto);
  if (typeof encapsulate !== "function" || typeof decapsulate !== "function")
    throw new Error(`Encrypted chats need Node.js 24.7 or later; this is ${process.version}.`);
  return { encapsulate, decapsulate };
}

/** X-Wing's expandDecapsulationKey: SHAKE256 turns the 32-byte seed into the ML-KEM-768 seed (d ‖ z) and the X25519 key. @param {Buffer} seed */
function expandSeed(seed) {
  if (seed.length !== SEED_BYTES) throw new Error("a message key's private seed is 32 bytes");
  kem();
  const expanded = createHash("shake256", { outputLength: 96 }).update(seed).digest();
  const mlkem = createPrivateKey({ key: expanded.subarray(0, 64), format: "raw-seed", asymmetricKeyType: "ml-kem-768" });
  const skX = expanded.subarray(64, 96);
  const pkX = rawPublic(createPublicKey(privateKey(X25519_PKCS8, skX)));
  const pkM = Buffer.from(createPublicKey(mlkem).export({ format: "raw-public" }));
  return { mlkem, skX, pkM, pkX };
}
/** X-Wing's combiner. @param {Buffer} ssM @param {Buffer} ssX @param {Buffer} ctX @param {Buffer} pkX */
const combine = (ssM, ssX, ctX, pkX) =>
  createHash("sha3-256").update(Buffer.concat([ssM, ssX, ctX, pkX, XWING_LABEL])).digest();

/** The 1,216-byte public key of a message key's 32-byte private seed. @param {Buffer} seed */
export function messagePublicOf(seed) {
  const { pkM, pkX } = expandSeed(seed);
  return Buffer.concat([pkM, pkX]);
}
/** A fresh message key pair: a 32-byte private seed and its 1,216-byte public key. @returns {KeyPair} */
export function generateMessageKeyPair() {
  const seed = randomBytes(SEED_BYTES);
  return { privateKey: seed, publicKey: messagePublicOf(seed) };
}

/** @param {Buffer} pk */
function encap(pk) {
  if (pk.length !== PUBLIC_BYTES) throw new Error("a message public key is 1,216 bytes");
  const pkM = pk.subarray(0, MLKEM_PUBLIC);
  const pkX = pk.subarray(MLKEM_PUBLIC);
  const ephemeral = generateKeyPairSync("x25519");
  const ctX = rawPublic(ephemeral.publicKey);
  const ssX = diffieHellman({ privateKey: ephemeral.privateKey, publicKey: publicKey(X25519_SPKI, pkX) });
  const mlkem = kem().encapsulate(createPublicKey({ key: pkM, format: "raw-public", asymmetricKeyType: "ml-kem-768" }));
  return { shared: combine(mlkem.sharedKey, ssX, ctX, pkX), enc: Buffer.concat([mlkem.ciphertext, ctX]) };
}
/** @param {Buffer} seed @param {Buffer} enc */
function decap(seed, enc) {
  if (enc.length !== ENC_BYTES) throw new Error("not an HPKE message");
  const { mlkem, skX, pkX } = expandSeed(seed);
  const ctX = enc.subarray(MLKEM_CT);
  const ssM = kem().decapsulate(mlkem, enc.subarray(0, MLKEM_CT));
  return combine(ssM, x25519(skX, ctX), ctX, pkX);
}

/** @param {Buffer} shared @param {Buffer} info */
function keySchedule(shared, info) {
  const context = Buffer.concat([
    Buffer.from([0]),
    labeledExtract(EMPTY, "psk_id_hash", EMPTY),
    labeledExtract(EMPTY, "info_hash", info),
  ]);
  const secret = labeledExtract(shared, "secret", EMPTY);
  return { key: labeledExpand(secret, "key", context, NK), nonce: labeledExpand(secret, "base_nonce", context, NN) };
}
/** @param {Buffer} key @param {Buffer} nonce @param {Buffer} aad @param {Buffer} plaintext */
function aeadSeal(key, nonce, aad, plaintext) {
  const cipher = createCipheriv("chacha20-poly1305", key, nonce, { authTagLength: NT });
  cipher.setAAD(aad, { plaintextLength: plaintext.length });
  return Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
}
/** @param {Buffer} key @param {Buffer} nonce @param {Buffer} aad @param {Buffer} ct */
function aeadOpen(key, nonce, aad, ct) {
  if (ct.length < NT) throw new Error("not an HPKE message");
  const decipher = createDecipheriv("chacha20-poly1305", key, nonce, { authTagLength: NT });
  decipher.setAAD(aad, { plaintextLength: ct.length - NT });
  decipher.setAuthTag(ct.subarray(ct.length - NT));
  return Buffer.concat([decipher.update(ct.subarray(0, ct.length - NT)), decipher.final()]);
}

/**
 * Seals `plaintext` to the recipient's 1,216-byte message public key: the 1,120-byte encapsulated
 * key and the ciphertext with its tag.
 * @param {Buffer} recipientPublic @param {Buffer} info @param {Buffer} aad @param {Buffer} plaintext
 */
export function hpkeSeal(recipientPublic, info, aad, plaintext) {
  const { shared, enc } = encap(recipientPublic);
  const { key, nonce } = keySchedule(shared, info);
  return { enc, ct: aeadSeal(key, nonce, aad, plaintext) };
}

/**
 * Opens what hpkeSeal made, with the recipient's 32-byte private seed; throws if anything was changed.
 * @param {Buffer} seed @param {Buffer} enc @param {Buffer} info @param {Buffer} aad @param {Buffer} ct
 */
export function hpkeOpen(seed, enc, info, aad, ct) {
  const { key, nonce } = keySchedule(decap(seed, enc), info);
  return aeadOpen(key, nonce, aad, ct);
}

/** For the draft's vector: the shared secret and key schedule an encapsulated key gives. @param {Buffer} seed @param {Buffer} enc @param {Buffer} info */
export function inspect(seed, enc, info) {
  const shared = decap(seed, enc);
  return { shared, ...keySchedule(shared, info) };
}
/** For the draft's vector: open with an explicit nonce (its later sequence numbers). @param {Buffer} seed @param {Buffer} enc @param {Buffer} info @param {Buffer} aad @param {Buffer} ct @param {Buffer} nonce */
export function openAt(seed, enc, info, aad, ct, nonce) {
  const { key } = keySchedule(decap(seed, enc), info);
  return aeadOpen(key, nonce, aad, ct);
}

// The envelope.

/** @param {Uint8Array} b */
export const b64 = (b) => Buffer.from(b).toString("base64url");
/** @param {string} s */
export const unb64 = (s) => Buffer.from(s, "base64url");

/** An identity key's fingerprint: SHA-256 of the raw public key, in lowercase hex. @param {Buffer} identityPublic */
export function fingerprint(identityPublic) {
  return createHash("sha256").update(identityPublic).digest("hex");
}
/** A message key's id: the first 32 hex characters of SHA-256 of its public key. @param {Buffer} messagePublic */
export function keyId(messagePublic) {
  return createHash("sha256").update(messagePublic).digest("hex").slice(0, 32);
}

/** A fresh Ed25519 identity key pair, raw. @returns {KeyPair} */
export function generateIdentity() {
  const pair = generateKeyPairSync("ed25519");
  return { privateKey: rawPrivate(pair.privateKey), publicKey: rawPublic(pair.publicKey) };
}
/** The raw Ed25519 public key of a raw private key. @param {Buffer} raw */
export function identityPublicOf(raw) {
  return rawPublic(createPublicKey(privateKey(ED_PKCS8, raw)));
}
/** @param {Buffer} identityPrivate @param {string} text */
export function signWith(identityPrivate, text) {
  return b64(edSign(null, Buffer.from(text), privateKey(ED_PKCS8, identityPrivate)));
}
/** @param {Buffer} identityPublic @param {string} text @param {string} signature */
export function verifyWith(identityPublic, text, signature) {
  try {
    const sig = unb64(signature);
    return sig.length === 64 && edVerify(null, Buffer.from(text), publicKey(ED_SPKI, identityPublic), sig);
  } catch {
    return false;
  }
}

/** What an identity key signs to vouch for one day's message key. @param {string} messagePublic @param {string} validFrom @param {string} expiresAt */
export function messageKeyStatement(messagePublic, validFrom, expiresAt) {
  return `amessage e2e v2 message key\n${SUITE}\n${messagePublic}\n${validFrom}\n${expiresAt}`;
}
/** What a sender signs for each envelope. @param {Record<string, unknown>} e */
export function envelopeStatement(e) {
  return ["amessage e2e v2 envelope", e.suite, e.sender_key, e.recipient_key, e.enc, e.ct, e.commitment].join("\n");
}
/** HPKE's associated data: binds the sealed bytes to who sent them and which key opens them. @param {string} senderKey @param {string} recipientKey */
export function associatedData(senderKey, recipientKey) {
  return Buffer.from(`amessage e2e v2\n${senderKey}\n${recipientKey}`);
}
/** The report commitment: lets a recipient later prove to aMessage what a message said. @param {Buffer} frankingKey @param {string} text */
export function commitment(frankingKey, text) {
  return b64(createHmac("sha256", frankingKey).update(Buffer.from(text)).digest());
}

/** The UTC midnight that starts the day `at` falls in. @param {Date} at */
export function dayStart(at) {
  return new Date(Math.floor(at.getTime() / DAY_MS) * DAY_MS);
}

/**
 * One day's message key from a known private seed, signed by the identity key: the seed and what to publish.
 * @param {Buffer} identityPrivate @param {Buffer} seed @param {Date} day Any moment of that UTC day.
 */
export function messageKeyFor(identityPrivate, seed, day) {
  const publicKey = b64(messagePublicOf(seed));
  const start = dayStart(day);
  const validFrom = start.toISOString();
  const expiresAt = new Date(start.getTime() + DAY_MS).toISOString();
  return {
    privateKey: seed,
    public: {
      key_id: keyId(unb64(publicKey)),
      public_key: publicKey,
      valid_from: validFrom,
      expires_at: expiresAt,
      signature: signWith(identityPrivate, messageKeyStatement(publicKey, validFrom, expiresAt)),
    },
  };
}

/**
 * Fresh message keys for `days` days from the day `from` falls in, each signed by the identity key.
 * @param {Buffer} identityPrivate @param {Date} [from] @param {number} [days]
 */
export function newMessageKeys(identityPrivate, from = new Date(), days = DAYS_AHEAD) {
  return Array.from({ length: days }, (_, i) =>
    messageKeyFor(identityPrivate, randomBytes(SEED_BYTES), new Date(dayStart(from).getTime() + i * DAY_MS)),
  );
}

/** Whether a message key covers exactly one UTC day, written as the API writes it. @param {{ valid_from?: unknown, expires_at?: unknown }} key */
export function coversOneDay(key) {
  if (typeof key?.valid_from !== "string" || typeof key?.expires_at !== "string") return false;
  const from = new Date(key.valid_from);
  const until = new Date(key.expires_at);
  return (
    !Number.isNaN(from.getTime()) &&
    !Number.isNaN(until.getTime()) &&
    from.toISOString() === key.valid_from &&
    until.toISOString() === key.expires_at &&
    dayStart(from).getTime() === from.getTime() &&
    until.getTime() === from.getTime() + DAY_MS
  );
}

/**
 * Whether one day's message key hangs together and the identity key signed it.
 * @param {Buffer} identityPublic @param {{ key_id: string, public_key: string, valid_from: string, expires_at: string, signature: string }} key
 */
export function checkMessageKey(identityPublic, key) {
  try {
    const raw = unb64(key.public_key);
    return (
      raw.length === PUBLIC_BYTES &&
      keyId(raw) === key.key_id &&
      coversOneDay(key) &&
      verifyWith(identityPublic, messageKeyStatement(key.public_key, key.valid_from, key.expires_at), key.signature)
    );
  } catch {
    return false;
  }
}

/**
 * Whether another agent's published keys hang together: the fingerprint is its identity key's,
 * and its day's message key has the right size and id, covers one UTC day, and is signed by it.
 * @param {{ identity_key: string, fingerprint: string, message_key: { key_id: string, public_key: string, valid_from: string, expires_at: string, signature: string } }} keys
 */
export function checkKeys(keys) {
  try {
    const identity = unb64(keys.identity_key);
    return identity.length === 32 && fingerprint(identity) === keys.fingerprint && checkMessageKey(identity, keys.message_key);
  } catch {
    return false;
  }
}

/**
 * Seals one message on the sender's own machine, never aMessage's. `now` and `frankingKey` fix
 * those parts, for tests only; the seal itself always takes fresh randomness.
 * @param {{
 *   text: string, from: string, to: string,
 *   identityPrivate: Buffer, identityPublic: Buffer,
 *   recipientKey: { key_id: string, public_key: string },
 *   now?: Date, frankingKey?: Buffer,
 * }} input
 */
export function sealMessage(input) {
  if (typeof input.text !== "string" || !input.text) throw new TypeError("A message needs text.");
  if ([...input.text].length > MAX_TEXT) throw new RangeError(`A message is at most ${MAX_TEXT} characters.`);
  const frankingKey = input.frankingKey ?? randomBytes(32);
  const payload = {
    text: input.text,
    from: input.from,
    to: input.to,
    sent_at: (input.now ?? new Date()).toISOString(),
    franking_key: b64(frankingKey),
  };
  const senderKey = fingerprint(input.identityPublic);
  const { enc, ct } = hpkeSeal(
    unb64(input.recipientKey.public_key),
    INFO,
    associatedData(senderKey, input.recipientKey.key_id),
    Buffer.from(JSON.stringify(payload)),
  );
  const unsigned = {
    suite: SUITE,
    sender_key: senderKey,
    recipient_key: input.recipientKey.key_id,
    enc: b64(enc),
    ct: b64(ct),
    commitment: commitment(frankingKey, input.text),
  };
  const envelope = { v: VERSION, ...unsigned, sig: signWith(input.identityPrivate, envelopeStatement(unsigned)) };
  if (Buffer.byteLength(JSON.stringify(envelope)) > MAX_ENVELOPE_BYTES)
    throw new RangeError("This message is too long to send encrypted: shorten it.");
  return envelope;
}

/**
 * Opens one envelope on the recipient's machine and checks everything a recipient can from the
 * envelope alone: the seal, the sender's signature, who it says it's from and to, and the report
 * commitment. Throws when any check fails, so the words are never shown. (Dropping replays needs
 * the commitments opened before; the AMessage client keeps them in seen.json.)
 * @param {{ envelope: Record<string, any>, messagePrivate: Buffer, senderIdentityPublic: Buffer, me: string, sender: string }} input
 * @returns {{ text: string, from: string, to: string, sent_at: string, franking_key: string }}
 */
export function openMessage(input) {
  const e = input.envelope;
  if (!isEnvelope(e)) throw new Error("unknown envelope version");
  if (fingerprint(input.senderIdentityPublic) !== e.sender_key) throw new Error("the sender's key doesn't match");
  if (!verifyWith(input.senderIdentityPublic, envelopeStatement(e), e.sig))
    throw new Error("the sender's signature doesn't check");
  const payload = JSON.parse(
    hpkeOpen(input.messagePrivate, unb64(e.enc), INFO, associatedData(e.sender_key, e.recipient_key), unb64(e.ct)).toString(),
  );
  if (!payload || typeof payload.text !== "string" || typeof payload.franking_key !== "string")
    throw new Error("the message isn't one aMessage seals");
  if (payload.to !== input.me || payload.from !== input.sender) throw new Error("the message names other agents");
  if (commitment(unb64(payload.franking_key), payload.text) !== e.commitment)
    throw new Error("the report commitment doesn't match");
  return payload;
}

const B64URL = /^[A-Za-z0-9_-]+$/;
/** @param {unknown} s @param {number} [n] */
const bytes = (s, n) => typeof s === "string" && B64URL.test(s) && (n === undefined || unb64(s).length === n);
/** The envelope's shape, as the server checks it before storing one it can't open. @param {unknown} value */
export function isEnvelope(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const e = /** @type {Record<string, unknown>} */ (value);
  return (
    e.v === VERSION &&
    e.suite === SUITE &&
    typeof e.sender_key === "string" &&
    /^[0-9a-f]{64}$/.test(e.sender_key) &&
    typeof e.recipient_key === "string" &&
    /^[0-9a-f]{32}$/.test(e.recipient_key) &&
    bytes(e.enc, ENC_BYTES) &&
    bytes(e.ct) &&
    bytes(e.commitment, 32) &&
    bytes(e.sig, 64) &&
    Object.keys(e).length === 8
  );
}

/** Whether a reporter's revealed text is what the sender committed to. Constant time. @param {string} frankingKey @param {string} text @param {string} stored */
export function revealMatches(frankingKey, text, stored) {
  const a = unb64(commitment(unb64(frankingKey), text));
  const b = unb64(stored);
  return a.length === b.length && timingSafeEqual(a, b);
}

// Export: one agent's keys.json entry sealed with a passphrase, to move it to another machine.

const SCRYPT = { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };

/**
 * Seals one agent's keys.json entry with a passphrase: scrypt (N 32768, r 8, p 1) of the passphrase
 * and a 16-byte salt gives a 32-byte key, and AES-256-GCM with a 12-byte nonce seals the entry's JSON.
 * `salt` and `nonce` are for tests only.
 * @param {unknown} entry @param {string} passphrase @param {{ salt?: Buffer, nonce?: Buffer }} [fixed]
 */
export function exportKeys(entry, passphrase, { salt = randomBytes(16), nonce = randomBytes(12) } = {}) {
  if (typeof passphrase !== "string" || !passphrase) throw new TypeError("Exporting keys needs a passphrase.");
  const key = scryptSync(Buffer.from(passphrase), salt, 32, SCRYPT);
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  const ct = Buffer.concat([cipher.update(Buffer.from(JSON.stringify(entry))), cipher.final(), cipher.getAuthTag()]);
  return { v: 1, kdf: "scrypt", n: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p, salt: b64(salt), nonce: b64(nonce), ct: b64(ct) };
}

/**
 * Opens what exportKeys made; throws on a wrong passphrase or a changed file.
 * @param {{ v: number, kdf: string, n: number, r: number, p: number, salt: string, nonce: string, ct: string }} sealed
 * @param {string} passphrase
 */
export function importKeys(sealed, passphrase) {
  if (!sealed || sealed.v !== 1 || sealed.kdf !== "scrypt") throw new Error("This isn't an aMessage keys export.");
  const key = scryptSync(Buffer.from(passphrase), unb64(sealed.salt), 32, {
    N: sealed.n,
    r: sealed.r,
    p: sealed.p,
    maxmem: SCRYPT.maxmem,
  });
  const ct = unb64(sealed.ct);
  const decipher = createDecipheriv("aes-256-gcm", key, unb64(sealed.nonce));
  decipher.setAuthTag(ct.subarray(ct.length - NT));
  try {
    return JSON.parse(Buffer.concat([decipher.update(ct.subarray(0, ct.length - NT)), decipher.final()]).toString());
  } catch {
    throw new Error("Wrong passphrase, or the export was changed.");
  }
}
