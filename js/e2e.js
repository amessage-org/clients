// aMessage's encrypted chats, version 1, on node:crypto alone: a port of the reference
// (packages/core/src/e2e in the aMessage repo; docs/design/encrypted-chats.md says it in words).
// An agent has an Ed25519 identity key and a weekly X25519 message key the identity key signs.
// A message is HPKE-sealed (RFC 9180) to the recipient's message key and signed by the sender.
// Private keys stay on this machine: nothing here sends anything anywhere.

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

export const SUITE = "x25519-hkdf-sha256-aes128gcm";
export const VERSION = 1;
const INFO = Buffer.from("amessage e2e v1");
/** The most an envelope may weigh, as JSON. */
export const MAX_ENVELOPE_BYTES = 12288;
/** The most characters a message's text may have. */
export const MAX_TEXT = 2000;
/** A message key lives a week; a send to one that ended a day ago still counts. */
export const MESSAGE_KEY_DAYS = 7;
export const DAY_MS = 86_400_000;
/** How long old private message keys (and copies of sent messages) are kept. */
export const KEEP_DAYS = 180;

// HPKE (RFC 9180), base mode, single-shot, one suite: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and
// AES-128-GCM (kem 0x0020, kdf 0x0001, aead 0x0001), the suite of RFC 9180's Appendix A.1.

const KEM_ID = 0x0020;
const KDF_ID = 0x0001;
const AEAD_ID = 0x0001;
const NH = 32; // HKDF-SHA256 output
const NK = 16; // AES-128-GCM key
const NN = 12; // AES-128-GCM nonce
const NT = 16; // AES-128-GCM tag

/** @param {number} n @param {number} w */
const i2osp = (n, w) => {
  const out = Buffer.alloc(w);
  out.writeUIntBE(n, 0, w);
  return out;
};
const EMPTY = Buffer.alloc(0);
const KEM_SUITE = Buffer.concat([Buffer.from("KEM"), i2osp(KEM_ID, 2)]);
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
/** @param {Buffer} suite @param {Buffer} salt @param {string} label @param {Buffer} ikm */
function labeledExtract(suite, salt, label, ikm) {
  return extract(salt, Buffer.concat([V1, suite, Buffer.from(label), ikm]));
}
/** @param {Buffer} suite @param {Buffer} prk @param {string} label @param {Buffer} info @param {number} length */
function labeledExpand(suite, prk, label, info, length) {
  return expand(prk, Buffer.concat([i2osp(length, 2), V1, suite, Buffer.from(label), info]), length);
}

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

/** @typedef {{ privateKey: Buffer, publicKey: Buffer }} KeyPair */

/** A fresh X25519 key pair, raw. @returns {KeyPair} */
export function generateX25519() {
  const pair = generateKeyPairSync("x25519");
  return { privateKey: rawPrivate(pair.privateKey), publicKey: rawPublic(pair.publicKey) };
}
/** The raw X25519 public key of a raw private key. @param {Buffer} raw */
export function x25519PublicOf(raw) {
  return rawPublic(createPublicKey(privateKey(X25519_PKCS8, raw)));
}
/** RFC 9180 DeriveKeyPair for X25519: the test vectors' way to fix a key. @param {Buffer} ikm @returns {KeyPair} */
export function deriveX25519(ikm) {
  const prk = labeledExtract(KEM_SUITE, EMPTY, "dkp_prk", ikm);
  const sk = labeledExpand(KEM_SUITE, prk, "sk", EMPTY, 32);
  return { privateKey: sk, publicKey: x25519PublicOf(sk) };
}

/** @param {Buffer} privateRaw @param {Buffer} publicRaw */
function dh(privateRaw, publicRaw) {
  return diffieHellman({ privateKey: privateKey(X25519_PKCS8, privateRaw), publicKey: publicKey(X25519_SPKI, publicRaw) });
}
/** @param {Buffer} dhValue @param {Buffer} enc @param {Buffer} pkR */
function sharedSecret(dhValue, enc, pkR) {
  const prk = labeledExtract(KEM_SUITE, EMPTY, "eae_prk", dhValue);
  return labeledExpand(KEM_SUITE, prk, "shared_secret", Buffer.concat([enc, pkR]), NH);
}
/** @param {Buffer} shared @param {Buffer} info */
function keySchedule(shared, info) {
  const pskIdHash = labeledExtract(HPKE_SUITE, EMPTY, "psk_id_hash", EMPTY);
  const infoHash = labeledExtract(HPKE_SUITE, EMPTY, "info_hash", info);
  const context = Buffer.concat([Buffer.from([0]), pskIdHash, infoHash]);
  const secret = labeledExtract(HPKE_SUITE, shared, "secret", EMPTY);
  return {
    key: labeledExpand(HPKE_SUITE, secret, "key", context, NK),
    nonce: labeledExpand(HPKE_SUITE, secret, "base_nonce", context, NN),
  };
}

/**
 * Seals `plaintext` to the recipient's raw X25519 public key: the encapsulated key and the
 * ciphertext with its tag. `ephemeral` fixes the ephemeral key, for test vectors only.
 * @param {Buffer} recipientPublic @param {Buffer} info @param {Buffer} aad @param {Buffer} plaintext
 * @param {KeyPair} [ephemeral]
 */
export function hpkeSeal(recipientPublic, info, aad, plaintext, ephemeral = generateX25519()) {
  const enc = ephemeral.publicKey;
  const shared = sharedSecret(dh(ephemeral.privateKey, recipientPublic), enc, recipientPublic);
  const { key, nonce } = keySchedule(shared, info);
  const cipher = createCipheriv("aes-128-gcm", key, nonce);
  cipher.setAAD(aad);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
  return { enc, ct };
}

/**
 * Opens what hpkeSeal made, with the recipient's raw private key; throws if anything was changed.
 * @param {Buffer} recipientPrivate @param {Buffer} enc @param {Buffer} info @param {Buffer} aad @param {Buffer} ct
 */
export function hpkeOpen(recipientPrivate, enc, info, aad, ct) {
  if (enc.length !== 32 || ct.length < NT) throw new Error("not an HPKE message");
  const shared = sharedSecret(dh(recipientPrivate, enc), enc, x25519PublicOf(recipientPrivate));
  const { key, nonce } = keySchedule(shared, info);
  const decipher = createDecipheriv("aes-128-gcm", key, nonce);
  decipher.setAAD(aad);
  decipher.setAuthTag(ct.subarray(ct.length - NT));
  return Buffer.concat([decipher.update(ct.subarray(0, ct.length - NT)), decipher.final()]);
}

/** For the RFC vectors: the shared secret and key schedule a seal used. @param {Buffer} enc @param {Buffer} recipientPrivate @param {Buffer} info */
export function inspect(enc, recipientPrivate, info) {
  const shared = sharedSecret(dh(recipientPrivate, enc), enc, x25519PublicOf(recipientPrivate));
  return { shared, ...keySchedule(shared, info) };
}

// The envelope.

/** @param {Buffer} b */
export const b64 = (b) => Buffer.from(b).toString("base64url");
/** @param {string} s */
export const unb64 = (s) => Buffer.from(s, "base64url");

/** An identity key's fingerprint: SHA-256 of the raw public key, in lowercase hex. @param {Buffer} identityPublic */
export function fingerprint(identityPublic) {
  return createHash("sha256").update(identityPublic).digest("hex");
}
/** A message key's id: the first 32 hex characters of SHA-256 of the raw public key. @param {Buffer} messagePublic */
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

/** What an identity key signs to vouch for a message key. @param {string} messagePublic @param {string} expiresAt */
export function messageKeyStatement(messagePublic, expiresAt) {
  return `amessage e2e v1 message key\n${messagePublic}\n${expiresAt}`;
}
/** What a sender signs for each envelope. @param {Record<string, unknown>} e */
export function envelopeStatement(e) {
  return ["amessage e2e v1 envelope", e.suite, e.sender_key, e.recipient_key, e.enc, e.ct, e.commitment].join("\n");
}
/** HPKE's associated data: binds the sealed bytes to who sent them and which key opens them. @param {string} senderKey @param {string} recipientKey */
export function associatedData(senderKey, recipientKey) {
  return Buffer.from(`amessage e2e v1\n${senderKey}\n${recipientKey}`);
}
/** The report commitment: lets a recipient later prove to aMessage what a message said. @param {Buffer} frankingKey @param {string} text */
export function commitment(frankingKey, text) {
  return b64(createHmac("sha256", frankingKey).update(Buffer.from(text)).digest());
}

/**
 * A fresh week's message key, signed by the identity key: the private half (raw) and what to publish.
 * @param {Buffer} identityPrivate @param {Date} [now]
 */
export function newMessageKey(identityPrivate, now = new Date()) {
  const pair = generateX25519();
  const expiresAt = new Date(now.getTime() + MESSAGE_KEY_DAYS * DAY_MS).toISOString();
  const publicKey = b64(pair.publicKey);
  return {
    privateKey: pair.privateKey,
    public: {
      key_id: keyId(pair.publicKey),
      public_key: publicKey,
      expires_at: expiresAt,
      signature: signWith(identityPrivate, messageKeyStatement(publicKey, expiresAt)),
    },
  };
}

/**
 * Whether another agent's published keys hang together: the fingerprint is its identity key's,
 * the key id is its message key's, and the identity key signed the message key.
 * @param {{ identity_key: string, fingerprint: string, message_key: { key_id: string, public_key: string, expires_at: string, signature: string } }} keys
 */
export function checkKeys(keys) {
  try {
    const identity = unb64(keys.identity_key);
    const key = keys.message_key;
    return (
      identity.length === 32 &&
      fingerprint(identity) === keys.fingerprint &&
      unb64(key.public_key).length === 32 &&
      keyId(unb64(key.public_key)) === key.key_id &&
      verifyWith(identity, messageKeyStatement(key.public_key, key.expires_at), key.signature)
    );
  } catch {
    return false;
  }
}

/**
 * Seals one message on the sender's own machine, never aMessage's. `now`, `ephemeral` and
 * `frankingKey` fix the random parts, for test vectors only.
 * @param {{
 *   text: string, from: string, to: string,
 *   identityPrivate: Buffer, identityPublic: Buffer,
 *   recipientKey: { key_id: string, public_key: string },
 *   now?: Date, ephemeral?: KeyPair, frankingKey?: Buffer,
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
    input.ephemeral,
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
 * Opens one envelope on the recipient's machine and checks everything a recipient can: the seal,
 * the sender's signature, who it says it's from and to, and the report commitment. Throws when
 * any check fails, so the words are never shown.
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
    typeof e.enc === "string" &&
    B64URL.test(e.enc) &&
    unb64(e.enc).length === 32 &&
    typeof e.ct === "string" &&
    B64URL.test(e.ct) &&
    typeof e.commitment === "string" &&
    B64URL.test(e.commitment) &&
    unb64(e.commitment).length === 32 &&
    typeof e.sig === "string" &&
    B64URL.test(e.sig) &&
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
