// aMessage's encrypted chats, version 1: the building blocks AMessage uses. Raw keys are 32-byte Buffers.
import type { Envelope, MessageKey } from "./index.js";

export declare const SUITE: "x25519-hkdf-sha256-aes128gcm";
export declare const VERSION: 1;
export declare const MAX_ENVELOPE_BYTES: number;
export declare const MAX_TEXT: number;
export declare const MESSAGE_KEY_DAYS: number;
export declare const DAY_MS: number;
export declare const KEEP_DAYS: number;

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
export declare function generateX25519(): KeyPair;
export declare function x25519PublicOf(messagePrivate: Buffer): Buffer;
export declare function deriveX25519(ikm: Buffer): KeyPair;
export declare function signWith(identityPrivate: Buffer, text: string): string;
export declare function verifyWith(identityPublic: Buffer, text: string, signature: string): boolean;
export declare function messageKeyStatement(messagePublic: string, expiresAt: string): string;
export declare function envelopeStatement(envelope: Omit<Envelope, "v" | "sig">): string;
export declare function associatedData(senderKey: string, recipientKey: string): Buffer;
export declare function commitment(frankingKey: Buffer, text: string): string;
export declare function newMessageKey(identityPrivate: Buffer, now?: Date): { privateKey: Buffer; public: MessageKey };
export declare function checkKeys(keys: { identity_key: string; fingerprint: string; message_key: MessageKey }): boolean;
export declare function hpkeSeal(
  recipientPublic: Buffer,
  info: Buffer,
  aad: Buffer,
  plaintext: Buffer,
  ephemeral?: KeyPair,
): { enc: Buffer; ct: Buffer };
export declare function hpkeOpen(recipientPrivate: Buffer, enc: Buffer, info: Buffer, aad: Buffer, ct: Buffer): Buffer;
export declare function inspect(enc: Buffer, recipientPrivate: Buffer, info: Buffer): { shared: Buffer; key: Buffer; nonce: Buffer };
export declare function sealMessage(input: {
  text: string;
  from: string;
  to: string;
  identityPrivate: Buffer;
  identityPublic: Buffer;
  recipientKey: { key_id: string; public_key: string };
  now?: Date;
  ephemeral?: KeyPair;
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
