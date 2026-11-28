// aMessage's encrypted chats, version 2: the building blocks AMessage uses. Identity keys are raw
// 32-byte Ed25519 keys; a message key's private half is a 32-byte seed, its public half 1,216 bytes.
import type { Envelope, MessageKey } from "./index.js";

export declare const SUITE: "mlkem768x25519-hkdf-sha256-chacha20poly1305";
export declare const VERSION: 2;
export declare const MAX_ENVELOPE_BYTES: number;
export declare const MAX_TEXT: number;
export declare const DAY_MS: number;
/** Days of message keys published at a time. */
export declare const DAYS_AHEAD: number;
/** Publish again when fewer than this many days of keys are left. */
export declare const MIN_DAYS_LEFT: number;
export declare const KEEP_DAYS: number;
export declare const SEED_BYTES: number;
export declare const PUBLIC_BYTES: number;
export declare const ENC_BYTES: number;

export interface KeyPair {
  privateKey: Buffer;
  publicKey: Buffer;
}
export interface Payload {
  text: string;
  from: string;
  to: string;
  sent_at: string;
  franking_key: string;
}
export interface KeysExport {
  v: 1;
  kdf: "scrypt";
  n: number;
  r: number;
  p: number;
  salt: string;
  nonce: string;
  ct: string;
}

export declare function b64(bytes: Uint8Array): string;
export declare function unb64(text: string): Buffer;
export declare function fingerprint(identityPublic: Buffer): string;
export declare function keyId(messagePublic: Buffer): string;
export declare function generateIdentity(): KeyPair;
export declare function identityPublicOf(identityPrivate: Buffer): Buffer;
/** A fresh message key pair: a 32-byte private seed and its 1,216-byte public key. */
export declare function generateMessageKeyPair(): KeyPair;
/** The public key of a message key's private seed. */
export declare function messagePublicOf(seed: Buffer): Buffer;
export declare function signWith(identityPrivate: Buffer, text: string): string;
export declare function verifyWith(identityPublic: Buffer, text: string, signature: string): boolean;
export declare function messageKeyStatement(messagePublic: string, validFrom: string, expiresAt: string): string;
export declare function envelopeStatement(envelope: Omit<Envelope, "v" | "sig">): string;
export declare function associatedData(senderKey: string, recipientKey: string): Buffer;
export declare function commitment(frankingKey: Buffer, text: string): string;
/** The UTC midnight that starts the day `at` falls in. */
export declare function dayStart(at: Date): Date;
/** One day's message key from a known private seed, signed by the identity key. */
export declare function messageKeyFor(identityPrivate: Buffer, seed: Buffer, day: Date): { privateKey: Buffer; public: MessageKey };
/** Fresh message keys for `days` days (7 by default) from the day `from` falls in. */
export declare function newMessageKeys(
  identityPrivate: Buffer,
  from?: Date,
  days?: number,
): { privateKey: Buffer; public: MessageKey }[];
export declare function coversOneDay(key: { valid_from?: unknown; expires_at?: unknown }): boolean;
export declare function checkMessageKey(identityPublic: Buffer, key: MessageKey): boolean;
export declare function checkKeys(keys: { identity_key: string; fingerprint: string; message_key: MessageKey }): boolean;
export declare function hpkeSeal(recipientPublic: Buffer, info: Buffer, aad: Buffer, plaintext: Buffer): { enc: Buffer; ct: Buffer };
export declare function hpkeOpen(seed: Buffer, enc: Buffer, info: Buffer, aad: Buffer, ct: Buffer): Buffer;
export declare function inspect(seed: Buffer, enc: Buffer, info: Buffer): { shared: Buffer; key: Buffer; nonce: Buffer };
export declare function openAt(seed: Buffer, enc: Buffer, info: Buffer, aad: Buffer, ct: Buffer, nonce: Buffer): Buffer;
export declare function sealMessage(input: {
  text: string;
  from: string;
  to: string;
  identityPrivate: Buffer;
  identityPublic: Buffer;
  recipientKey: { key_id: string; public_key: string };
  now?: Date;
  frankingKey?: Buffer;
}): Envelope;
export declare function openMessage(input: {
  envelope: Envelope;
  messagePrivate: Buffer;
  senderIdentityPublic: Buffer;
  me: string;
  sender: string;
}): Payload;
export declare function isEnvelope(value: unknown): value is Envelope;
export declare function revealMatches(frankingKey: string, text: string, stored: string): boolean;
export declare function exportKeys(entry: unknown, passphrase: string, fixed?: { salt?: Buffer; nonce?: Buffer }): KeysExport;
export declare function importKeys(sealed: KeysExport, passphrase: string): any;
