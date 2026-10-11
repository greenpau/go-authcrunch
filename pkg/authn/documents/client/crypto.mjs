// Copyright 2026 Paul Greenberg greenpau@outlook.com
// Licensed under the Apache License, Version 2.0.
// Portable Web Crypto implementation of the Documents contract.
// Bundle this module with the separately maintained Documents application.

export const protocol = "authcrunch-documents";
export const chunkSize = 1048576;
const utf8 = new TextEncoder();
const text = new TextDecoder("utf-8", { fatal: true });
const zeroNonce = new Uint8Array(12);

export function encode(bytes) {
  let result = "";
  for (let i = 0; i < bytes.length; i += 8192) {
    result += String.fromCharCode(...bytes.subarray(i, i + 8192));
  }
  return btoa(result).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

export function decode(value, minimum = 0, maximum = chunkSize + 16) {
  if (typeof value !== "string" || value.length > Math.ceil(maximum * 4 / 3) || !/^[A-Za-z0-9_-]*$/.test(value)) throw new Error("Invalid binary encoding");
  const bytes = Uint8Array.from(atob(value.replaceAll("-", "+").replaceAll("_", "/")), c => c.charCodeAt(0));
  if (bytes.length < minimum || bytes.length > maximum || encode(bytes) !== value) throw new Error("Invalid binary length");
  return bytes;
}

function id(value) { decode(value, 32, 32); return value; }
function userID(value) {
  if (typeof value !== "string" || !/^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(value) || value === "00000000-0000-0000-0000-000000000000") throw new Error("Invalid local user ID");
  return value;
}
function context(...parts) { return utf8.encode(JSON.stringify([protocol, ...parts])); }
function random(length) { return crypto.getRandomValues(new Uint8Array(length)); }
async function digest(bytes) { return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)); }
async function derive(material, salt, info) {
  const key = await crypto.subtle.importKey("raw", material, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt, info }, key, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}
async function crypt(operation, material, info, bytes, salt, nonce = zeroNonce) {
  if (!(material instanceof Uint8Array) || material.length !== 32) throw new Error("Invalid key material");
  if (!(bytes instanceof Uint8Array)) throw new Error("Invalid binary input");
  // Snapshot before the first await, like SubtleCrypto itself. Callers may
  // clear or reuse their buffers immediately after starting an operation.
  // Uint8Array construction also copies Node Buffers, whose slice is a view.
  const input = new Uint8Array(material), data = new Uint8Array(bytes);
  try {
    const key = await derive(input, salt || await digest(utf8.encode(protocol)), info);
    return new Uint8Array(await crypto.subtle[operation]({ name: "AES-GCM", iv: nonce, additionalData: info, tagLength: 128 }, key, data));
  } finally { input.fill(0); data.fill(0); }
}
async function importPublic(value) {
  return crypto.subtle.importKey("raw", decode(value, 65, 65), { name: "ECDH", namedCurve: "P-256" }, false, []);
}
async function validatePublic(key) {
  userID(key.user_id); id(key.key_id);
  if (encode(await digest(decode(key.public_key, 65, 65))) !== key.key_id) throw new Error("Public key fingerprint mismatch");
  return importPublic(key.public_key);
}
function bootstrap(b) {
  if (b.protocol !== protocol || b.chunk_size !== chunkSize) throw new Error("Unsupported Documents protocol");
  id(b.portal_id); userID(b.user_id);
}
function fileContext(b, file, purpose, ...parts) {
  bootstrap(b); id(file.id); userID(file.owner);
  const plain = file.size - file.chunks * 16;
  const shape = describeSize(plain);
  if (shape.size !== file.size || shape.chunks !== file.chunks) throw new Error("Invalid document descriptor");
  return context(purpose, b.portal_id, file.owner, file.id, String(file.size), String(file.chunks), ...parts);
}

// Returns encrypted size, including GCM tags. The empty document has one chunk.
export function describeSize(plaintextBytes) {
  if (!Number.isSafeInteger(plaintextBytes) || plaintextBytes < 0 || plaintextBytes > 4 * 1024 ** 3 - 65536) throw new Error("Invalid document size");
  const chunks = Math.max(1, Math.ceil(plaintextBytes / chunkSize));
  return { chunks, size: plaintextBytes + chunks * 16 };
}

// The caller must have the user save recoveryKey BEFORE key.register. It is a
// high-entropy secret, not a login password, and must never be sent to the API.
export async function enroll(b) {
  b = { ...b };
  bootstrap(b);
  const pair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  const jwk = await crypto.subtle.exportKey("jwk", pair.privateKey);
  const recovery = random(32), salt = random(32), nonce = random(12);
  const key = { user_id: b.user_id, key_id: encode(await digest(raw)), public_key: encode(raw) };
  const info = context("vault", b.portal_id, b.user_id, key.key_id);
  const scalar = decode(jwk.d, 32, 32);
  try {
    key.vault = { salt: encode(salt), nonce: encode(nonce), ciphertext: encode(await crypt("encrypt", recovery, info, scalar, salt, nonce)) };
    return { registration: key, recoveryKey: encode(recovery) };
  } finally { scalar.fill(0); recovery.fill(0); }
}

// Unlock imports a non-exportable private key and verifies its public binding.
// JS cannot guarantee erasure of strings or engine-managed CryptoKey memory.
export async function unlock(b, registration, recoveryKey) {
  b = { ...b };
  registration = { ...registration, vault: registration?.vault && { ...registration.vault } };
  bootstrap(b);
  if (registration.user_id !== b.user_id || !registration.vault) throw new Error("Wrong vault owner");
  const publicKey = await validatePublic(registration);
  const vault = registration.vault;
  const recovery = decode(recoveryKey, 32, 32);
  let scalar;
  try {
    scalar = await crypt("decrypt", recovery, context("vault", b.portal_id, b.user_id, registration.key_id), decode(vault.ciphertext, 48, 48), decode(vault.salt, 32, 32), decode(vault.nonce, 12, 12));
    const raw = decode(registration.public_key, 65, 65);
    const privateKey = await crypto.subtle.importKey("jwk", { kty: "EC", crv: "P-256", x: encode(raw.subarray(1, 33)), y: encode(raw.subarray(33)), d: encode(scalar) }, { name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
    const check = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
    const left = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: check.publicKey }, privateKey, 256));
    const right = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: publicKey }, check.privateKey, 256));
    if (!left.every((v, i) => v === right[i])) throw new Error("Vault key mismatch");
    left.fill(0); right.fill(0);
    return privateKey;
  } finally { recovery.fill(0); scalar?.fill(0); }
}

export async function wrapKey(b, file, recipient, documentKey) {
  b = { ...b }; file = { ...file }; recipient = { ...recipient };
  if (!(documentKey instanceof Uint8Array) || documentKey.length !== 32) throw new Error("Invalid document key");
  const input = new Uint8Array(documentKey);
  let shared;
  try {
    const publicKey = await validatePublic(recipient);
    const ephemeral = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
    const encoded = encode(new Uint8Array(await crypto.subtle.exportKey("raw", ephemeral.publicKey)));
    shared = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: publicKey }, ephemeral.privateKey, 256));
    const info = fileContext(b, file, "envelope", recipient.user_id, recipient.key_id, encoded);
    return { key_id: recipient.key_id, ephemeral_key: encoded, ciphertext: encode(await crypt("encrypt", shared, info, input)) };
  } finally { input.fill(0); shared?.fill(0); }
}

export async function unwrapKey(b, file, registration, privateKey) {
  b = { ...b }; registration = { ...registration };
  file = { ...file, envelope: file?.envelope && { ...file.envelope } };
  bootstrap(b);
  if (registration.user_id !== b.user_id || file.envelope?.key_id !== registration.key_id) throw new Error("Wrong envelope recipient");
  await validatePublic(registration);
  const envelope = file.envelope;
  const publicKey = await importPublic(envelope.ephemeral_key);
  const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: publicKey }, privateKey, 256));
  try {
    return await crypt("decrypt", shared, fileContext(b, file, "envelope", b.user_id, envelope.key_id, envelope.ephemeral_key), decode(envelope.ciphertext, 48, 48));
  } finally { shared.fill(0); }
}

// Allocate on the server first. The returned closure encrypts each chunk once;
// retain its ciphertext for retries. A fresh prepareUpload creates a fresh key,
// so never mix chunks from two preparations into one allocated file.
export async function prepareUpload(b, file, owner, metadata) {
  b = { ...b }; file = { ...file }; owner = { ...owner };
  if (file.owner !== b.user_id || owner.user_id !== b.user_id || file.state !== "uploading") throw new Error("Wrong upload owner");
  validateMetadata(file, metadata);
  const info = fileContext(b, file, "metadata");
  const plain = utf8.encode(JSON.stringify(metadata));
  if (plain.length > 32752) throw new Error("Document metadata too large");
  const documentKey = random(32);
  const used = new Set();
  let disposed = false;
  try {
    const manifest = { metadata: encode(await crypt("encrypt", documentKey, info, plain)), envelope: await wrapKey(b, file, owner, documentKey) };
    return {
      manifest,
      async encryptChunk(number, bytes) {
        if (disposed || used.has(number)) throw new Error("Chunk encryption cannot be repeated");
        validateChunk(file, number, bytes.length + 16);
        used.add(number); // Reserve before await: concurrent calls cannot reuse a nonce.
        return crypt("encrypt", documentKey, fileContext(b, file, "chunk", String(number)), bytes);
      },
      dispose() { disposed = true; documentKey.fill(0); },
    };
  } catch (error) { documentKey.fill(0); throw error; }
  finally { plain.fill(0); }
}

function validateChunk(file, number, bytes) {
  if (!Number.isSafeInteger(number) || number < 0 || number >= file.chunks) throw new Error("Invalid chunk number");
  const expected = number === file.chunks - 1 ? file.size - number * (chunkSize + 16) : chunkSize + 16;
  if (bytes !== expected) throw new Error("Invalid chunk length");
}

export async function decryptMetadata(b, file, documentKey) {
  file = { ...file };
  const bytes = await crypt("decrypt", documentKey, fileContext(b, file, "metadata"), decode(file.metadata, 16, 32768));
  const value = JSON.parse(text.decode(bytes));
  validateMetadata(file, value);
  return value;
}

function validateMetadata(file, value) {
  if (!value || Array.isArray(value) || typeof value !== "object" || Object.keys(value).some(k => !["name", "type", "size"].includes(k)) || typeof value.name !== "string" || value.name.length === 0 || utf8.encode(value.name).length > 1024 || typeof value.type !== "string" || utf8.encode(value.type).length > 255 || value.size !== file.size - file.chunks * 16) throw new Error("Invalid document metadata");
}

export async function decryptChunk(b, file, documentKey, number, ciphertext) {
  validateChunk(file, number, ciphertext.length);
  return crypt("decrypt", documentKey, fileContext(b, file, "chunk", String(number)), ciphertext);
}
