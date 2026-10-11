// Copyright 2026 Paul Greenberg greenpau@outlook.com
// Licensed under the Apache License, Version 2.0.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const client = import("../../documents/client/crypto.mjs");

test("Documents vector and context tampering", async () => {
  const c = await client;
  const v = JSON.parse(fs.readFileSync(path.join(__dirname, "../../documents/testdata/protocol.json")));
  const privateKey = await c.unlock(v.bootstrap, v.registration, v.recoveryKey);
  assert.equal(privateKey.extractable, false);
  const key = await c.unwrapKey(v.bootstrap, v.file, v.registration, privateKey);
  assert.deepEqual(await c.decryptChunk(v.bootstrap, v.file, key, 0, c.decode(v.ciphertext)), c.decode(v.plaintext));
  assert.equal((await c.decryptMetadata(v.bootstrap, v.file, key)).name, "private-report.txt");
  const bad = c.decode(v.ciphertext); bad[0] ^= 1;
  await assert.rejects(c.decryptChunk(v.bootstrap, v.file, key, 0, bad));
  for (const field of ["id", "owner", "size", "chunks"]) {
    const changed = structuredClone(v.file);
    changed[field] = field === "owner" ? "00000000-0000-4000-8000-000000000099" : typeof changed[field] === "number" ? changed[field] + 1 : c.encode(new Uint8Array(32).fill(44));
    await assert.rejects(c.unwrapKey(v.bootstrap, changed, v.registration, privateKey));
  }
  const foreign = { ...v.bootstrap, portal_id: c.encode(new Uint8Array(32).fill(55)) };
  await assert.rejects(c.unlock(foreign, v.registration, v.recoveryKey));
  await assert.rejects(c.unwrapKey(foreign, v.file, v.registration, privateKey));
  await assert.rejects(c.unlock(v.bootstrap, v.registration, c.encode(new Uint8Array(32))));
  const modified = structuredClone(v.registration); modified.key_id = foreign.portal_id;
  await assert.rejects(c.unlock(v.bootstrap, modified, v.recoveryKey));
  assert.throws(() => c.decode(v.recoveryKey + "="));
});

test("Documents chunk separation, recipient encryption, and nonce reuse guard", async () => {
  const c = await client;
  const id = n => c.encode(new Uint8Array(32).fill(n));
  const b = { protocol: c.protocol, chunk_size: c.chunkSize, portal_id: id(1), user_id: "00000000-0000-4000-8000-000000000002" };
  const alice = await c.enroll(b);
  const file = { id: id(3), owner: b.user_id, ...c.describeSize(c.chunkSize * 2), state: "uploading" };
  const upload = await c.prepareUpload(b, file, alice.registration, { name: "secret.txt", type: "text/plain", size: c.chunkSize * 2 });
  const plaintext = new Uint8Array(c.chunkSize).fill(7);
  const [first, second] = await Promise.all([upload.encryptChunk(0, plaintext), upload.encryptChunk(1, plaintext)]);
  await assert.rejects(upload.encryptChunk(0, plaintext));
  assert.notDeepEqual(first, second);
  Object.assign(file, upload.manifest, { state: "ready" });
  const privateKey = await c.unlock(b, alice.registration, alice.recoveryKey);
  const key = await c.unwrapKey(b, file, alice.registration, privateKey);
  await assert.rejects(c.decryptChunk(b, file, key, 1, first));
  const bobBootstrap = { ...b, user_id: "00000000-0000-4000-8000-000000000004" }, bob = await c.enroll(bobBootstrap);
  const envelope = await c.wrapKey(b, file, bob.registration, key);
  const bobPrivate = await c.unlock(bobBootstrap, bob.registration, bob.recoveryKey);
  const bobKey = await c.unwrapKey(bobBootstrap, { ...file, envelope }, bob.registration, bobPrivate);
  assert.deepEqual(bobKey, key);
  assert.deepEqual(await c.decryptChunk(bobBootstrap, file, bobKey, 1, second), plaintext);
  await assert.rejects(c.unwrapKey(b, { ...file, envelope }, alice.registration, privateKey));
  upload.dispose();
  await assert.rejects(upload.encryptChunk(1, plaintext));
  assert.deepEqual(c.describeSize(0), { size: 16, chunks: 1 });
});

test("Documents empty files, metadata validation, and disposal during encryption", async () => {
  const c = await client;
  const id = n => c.encode(new Uint8Array(32).fill(n));
  const b = { protocol: c.protocol, chunk_size: c.chunkSize, portal_id: id(5), user_id: "00000000-0000-4000-8000-000000000006" };
  const owner = await c.enroll(b);
  const file = { id: id(7), owner: b.user_id, ...c.describeSize(0), state: "uploading" };
  const metadata = { name: "empty.txt", type: "", size: 0 };
  for (const invalid of [{ ...metadata, size: 1 }, { ...metadata, name: "" }, { ...metadata, name: "a".repeat(1025) }, { ...metadata, type: "x".repeat(256) }, { ...metadata, extra: "field" }]) {
    await assert.rejects(c.prepareUpload(b, file, owner.registration, invalid));
  }
  const upload = await c.prepareUpload(b, file, owner.registration, metadata);
  const work = upload.encryptChunk(0, new Uint8Array());
  upload.dispose();
  const ciphertext = await work;
  assert.equal(ciphertext.length, 16);
  const detail = { ...file, ...upload.manifest, state: "ready" };
  const privateKey = await c.unlock(b, owner.registration, owner.recoveryKey);
  const key = await c.unwrapKey(b, detail, owner.registration, privateKey);
  assert.deepEqual(await c.decryptChunk(b, detail, key, 0, ciphertext), new Uint8Array());
  assert.deepEqual(await c.decryptMetadata(b, detail, key), metadata);
  await assert.rejects(c.decryptChunk(b, detail, new Uint8Array(31), 0, ciphertext));
  key.fill(0);
});

test("Documents crypto snapshots byte buffers before asynchronous work", async () => {
  const c = await client;
  const v = JSON.parse(fs.readFileSync(path.join(__dirname, "../../documents/testdata/protocol.json")));
  const privateKey = await c.unlock(v.bootstrap, v.registration, v.recoveryKey);
  const key = await c.unwrapKey(v.bootstrap, v.file, v.registration, privateKey);
  const original = c.decode(v.plaintext);
  const file = { ...v.file, id:c.encode(new Uint8Array(32).fill(19)), state:"uploading" };
  const upload = await c.prepareUpload(v.bootstrap, file, v.registration, {name:"snapshot.txt",type:"",size:original.length});
  const input = original.slice();
  const encrypted = upload.encryptChunk(0, input);
  input.fill(0);
  // A concurrent duplicate must fail before the first encryption finishes.
  await assert.rejects(upload.encryptChunk(0, original));
  const detail = {...file, ...upload.manifest, state:"ready"};
  const uploadedKey = await c.unwrapKey(v.bootstrap, detail, v.registration, privateKey);
  assert.deepEqual(await c.decryptChunk(v.bootstrap, detail, uploadedKey, 0, await encrypted), original);
  upload.dispose(); uploadedKey.fill(0);

  const ciphertext = c.decode(v.ciphertext), keyBuffer = Buffer.from(key);
  const decrypted = c.decryptChunk(v.bootstrap, v.file, keyBuffer, 0, ciphertext);
  ciphertext.fill(0); keyBuffer.fill(0);
  assert.deepEqual(await decrypted, original);

  const retained = Buffer.from(key);
  await c.decryptChunk(v.bootstrap, v.file, retained, 0, c.decode(v.ciphertext));
  assert.deepEqual(new Uint8Array(retained), key, "helper must not clear a caller-owned Buffer");
  retained.fill(0);

  const wrappingInput = key.slice();
  const wrapping = c.wrapKey(v.bootstrap, v.file, v.registration, wrappingInput);
  wrappingInput.fill(0);
  const unwrapped = await c.unwrapKey(v.bootstrap, {...v.file, envelope:await wrapping}, v.registration, privateKey);
  assert.deepEqual(unwrapped, key);
  key.fill(0); unwrapped.fill(0);
});

test("Documents crypto snapshots account, recipient, vault and file context", async () => {
  const c = await client;
  const v = JSON.parse(fs.readFileSync(path.join(__dirname, "../../documents/testdata/protocol.json")));
  const bootstrap = {...v.bootstrap};
  const enrollment = c.enroll(bootstrap);
  bootstrap.user_id = "00000000-0000-4000-8000-000000000099";
  const enrolled = await enrollment;
  assert.equal(enrolled.registration.user_id, v.bootstrap.user_id);
  await c.unlock(v.bootstrap, enrolled.registration, enrolled.recoveryKey);

  const registration = structuredClone(v.registration);
  const unlocking = c.unlock(v.bootstrap, registration, v.recoveryKey);
  registration.vault.ciphertext = c.encode(new Uint8Array(48));
  registration.public_key = "changed";
  const privateKey = await unlocking;
  const detail = structuredClone(v.file);
  const unwrapping = c.unwrapKey(v.bootstrap, detail, v.registration, privateKey);
  detail.envelope.ciphertext = c.encode(new Uint8Array(48));
  detail.owner = bootstrap.user_id;
  const key = await unwrapping;
  const recipient = {...v.registration};
  const wrapping = c.wrapKey(v.bootstrap, v.file, recipient, key);
  recipient.key_id = "changed";
  recipient.public_key = "changed";
  const recovered = await c.unwrapKey(v.bootstrap, {...v.file,envelope:await wrapping}, v.registration, privateKey);
  assert.deepEqual(recovered, key);

  const metadataFile = {...v.file};
  const metadata = c.decryptMetadata(v.bootstrap, metadataFile, key);
  metadataFile.size += 1;
  assert.equal((await metadata).name, "private-report.txt");
  key.fill(0); recovered.fill(0);
});
