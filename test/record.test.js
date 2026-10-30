// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const Q = require('..');

function freshKey() {
  return Q.generateKey();
}

function manifestLaunch(key) {
  return Q.manifest({ key, vehicle: 'Quantova Heavy', pad: 'LC 39A', scheduledAt: '2026-12-01T12:00:00.000Z', operatorLabel: 'Quantova Launch' });
}

test('a manifested launch is a well formed signed record of the operator', () => {
  const operator = freshKey();
  const l = manifestLaunch(operator);
  assert.strictEqual(l.format, 'qlaunch/1');
  assert.strictEqual(l.type, 'manifest');
  assert.strictEqual(l.algorithm, 'ML-DSA-65');
  assert.strictEqual(l.signer.id, Q.keyId(operator));
  assert.strictEqual(l.statement.operatorKeyId, Q.keyId(operator));
  assert.match(l.statement.launchId, /^[0-9a-f]{32}$/);
  assert.strictEqual(Buffer.from(l.signer.publicKey, 'base64').length, Q.PUBLIC_KEY_BYTES);
  assert.strictEqual(Buffer.from(l.signature, 'base64').length, Q.SIGNATURE_BYTES);
});

test('the license, liftoff, deploy and outcome records chain to the same launch', () => {
  const operator = freshKey();
  const authority = freshKey();
  const provider = freshKey();
  const l = manifestLaunch(operator);
  const lic = Q.license({ key: authority, manifest: l });
  const off = Q.liftoff({ key: provider, record: lic });
  const dep = Q.deploy({ key: provider, record: off, payloadName: 'Quantova Sat 1', slot: 1 });
  const out = Q.outcome({ key: operator, record: dep, result: 'success' });
  assert.strictEqual(lic.statement.launchId, l.statement.launchId);
  assert.strictEqual(lic.statement.manifestRef, Q.recordRef(l));
  assert.strictEqual(off.statement.priorRef, Q.recordRef(lic));
  assert.strictEqual(dep.statement.priorRef, Q.recordRef(off));
  assert.strictEqual(out.statement.priorRef, Q.recordRef(dep));
  assert.strictEqual(out.statement.result, 'success');
});

test('invalid inputs are refused before anything is signed', () => {
  const key = freshKey();
  const base = { key, vehicle: 'V', pad: 'P', scheduledAt: '2026-12-01T12:00:00.000Z' };
  assert.throws(() => Q.manifest(Object.assign({}, base, { vehicle: '' })), /vehicle cannot be empty/);
  assert.throws(() => Q.manifest(Object.assign({}, base, { scheduledAt: 'soon' })), /scheduledAt must be an ISO/);
  assert.throws(() => Q.manifest(Object.assign({}, base, { unknownField: 1 })), /is not an option of manifest/);
  const l = manifestLaunch(key);
  assert.throws(() => Q.deploy({ key, record: l, payloadName: 'P', slot: 1.5 }), /slot must be a whole number/);
  assert.throws(() => Q.outcome({ key, record: l, result: 'kaboom' }), /result must be one of/);
});

test('a signing key must be a well formed 32 byte seed', () => {
  assert.throws(() => manifestLaunch(new Uint8Array(16)), /32 byte Uint8Array seed/);
  assert.throws(() => manifestLaunch(new Uint8Array(32)), /too few different byte values/);
});

test('a well formed record verifies and a type mismatch is invalid', async () => {
  const operator = freshKey();
  const l = manifestLaunch(operator);
  const ok = await Q.verify(l, { type: 'manifest', network: 'testnet', requireAnchor: false, strict: false });
  assert.strictEqual(ok.status, 'valid');
  assert.strictEqual(ok.type, 'manifest');
  assert.strictEqual(ok.launchId, l.statement.launchId);
  const wrongType = await Q.verify(l, { type: 'license', network: 'testnet', requireAnchor: false, strict: false });
  assert.strictEqual(wrongType.status, 'invalid');
  const wrongSigner = await Q.verify(l, { type: 'manifest', network: 'testnet', requireAnchor: false, strict: false, signerKeyId: Q.keyId(freshKey()) });
  assert.strictEqual(wrongSigner.status, 'invalid');
});

test('a tampered statement no longer verifies', async () => {
  const operator = freshKey();
  const l = manifestLaunch(operator);
  const forged = JSON.parse(JSON.stringify(l));
  forged.statement.pad = 'SLC 40';
  const r = await Q.verify(forged, { type: 'manifest', network: 'testnet', requireAnchor: false, strict: false });
  assert.strictEqual(r.status, 'invalid');
  assert.ok(r.checks.some((c) => c.name === 'signature' && !c.ok));
});

test('the prior link binds a record to the record before it', async () => {
  const operator = freshKey();
  const authority = freshKey();
  const l = manifestLaunch(operator);
  const lic = Q.license({ key: authority, manifest: l });
  const good = await Q.verify(lic, { type: 'license', network: 'testnet', requireAnchor: false, strict: false, prior: l });
  assert.ok(good.checks.some((c) => c.name === 'prior' && c.ok));
  const otherL = manifestLaunch(operator);
  const bad = await Q.verify(lic, { type: 'license', network: 'testnet', requireAnchor: false, strict: false, prior: otherL });
  assert.strictEqual(bad.status, 'invalid');
  assert.ok(bad.checks.some((c) => c.name === 'prior' && !c.ok));
});

test('launchRef is deterministic for the same secret and reference and differs otherwise', () => {
  const secret = new Uint8Array(32);
  globalThis.crypto.getRandomValues(secret);
  const a = Q.launchRef(secret, 'QHV 0001');
  const b = Q.launchRef(secret, 'QHV 0001');
  const c = Q.launchRef(secret, 'QHV 0002');
  assert.strictEqual(a, b);
  assert.notStrictEqual(a, c);
  assert.match(a, /^[0-9a-f]{64}$/);
});

test('the kind and constants are the ones pinned for the launch line', () => {
  assert.strictEqual(Q.KIND, 1408);
  assert.strictEqual(Q.FORMAT, 'qlaunch/1');
  assert.deepStrictEqual([...Q.TYPES], ['manifest', 'license', 'liftoff', 'deploy', 'outcome']);
  assert.deepStrictEqual([...Q.RESULTS], ['success', 'partial', 'failure']);
});
