// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const fs = require('fs');
const path = require('path');
const qstamp = require('@quantovainc/qstamp');
const native = require('./native');
const F = require('./format');

function requireProvingQstamp() {
  const dir = path.dirname(require.resolve('@quantovainc/qstamp/package.json'));
  const [major, minor] = String(require(path.join(dir, 'package.json')).version).split('.').map((n) => parseInt(n, 10));
  const released = major > 0 || (major === 0 && minor >= 3);
  const staged = fs.existsSync(path.join(dir, 'lib', 'deadline.js')) && fs.existsSync(path.join(dir, 'lib', 'finality.js'));
  if (typeof qstamp.isProven !== 'function' || !(released || staged)) {
    throw new Error('the installed Qstamp is older than 0.3.0 and cannot prove anchors');
  }
}
requireProvingQstamp();

function own(value) {
  if (value === undefined || value === null) return Object.create(null);
  if (typeof value !== 'object' || Array.isArray(value) || ArrayBuffer.isView(value) || value instanceof ArrayBuffer) F.reject('the options are a plain object');
  return Object.assign(Object.create(null), value);
}

function requireSeed(key) {
  if (!((ArrayBuffer.isView(key) && key instanceof Uint8Array) && key.length === 32 && key.buffer instanceof ArrayBuffer)) {
    F.reject('a signing key is a 32 byte Uint8Array seed, kept by its holder and wiped with fill(0) after use');
  }
  if (new Set(key).size < 13) F.reject('a signing key made of too few different byte values is refused, draw one with generateKey');
  return key;
}

function randomHex(n) {
  const b = new Uint8Array(n);
  globalThis.crypto.getRandomValues(b);
  return Buffer.from(b).toString('hex');
}

const HIDDEN = 'SecretKey [hidden]';

class SecretKey extends Uint8Array {
  static get [Symbol.species]() {
    return Uint8Array;
  }

  toJSON() {
    return HIDDEN;
  }

  toString() {
    return HIDDEN;
  }

  toLocaleString() {
    return HIDDEN;
  }

  [require('util').inspect.custom]() {
    return HIDDEN;
  }
}

function generateKey() {
  const seed = new SecretKey(32);
  globalThis.crypto.getRandomValues(seed);
  if (seed.every((b) => b === 0)) throw new Error('the secure random source returned only zeros');
  return seed;
}

function publicKey(key) {
  return native.publicKey(requireSeed(key));
}

function keyId(key) {
  return F.keyIdOf(publicKey(key));
}

function describeKey(key) {
  const pk = publicKey(key);
  return { format: 'qlaunch-key/1', algorithm: F.ALGORITHM, id: F.keyIdOf(pk), publicKey: Buffer.from(pk).toString('base64') };
}

function launchRef(secret, reference) {
  return F.launchRefOf(secret, reference);
}

function nowIso() {
  return new Date().toISOString();
}

function seal(type, key, statement) {
  const pk = publicKey(key);
  const id = F.keyIdOf(pk);
  let plain;
  try {
    plain = F.plainCopy(statement);
  } catch (e) {
    F.reject('the statement is not plain data');
  }
  const problem = F.statementProblem(type, plain);
  if (problem) F.reject(problem);
  const message = F.payload(type, plain);
  const rnd = new Uint8Array(32);
  globalThis.crypto.getRandomValues(rnd);
  let signature;
  try {
    signature = native.sign(key, message, rnd);
  } finally {
    rnd.fill(0);
  }
  if (!native.verify(pk, message, signature)) throw new Error('the new signature did not verify, nothing was produced');
  return {
    format: F.FORMAT,
    type,
    algorithm: F.ALGORITHM,
    signer: { id, publicKey: Buffer.from(pk).toString('base64') },
    statement: JSON.parse(JSON.stringify(plain)),
    signature: Buffer.from(signature).toString('base64'),
  };
}

function badLaunch(message) {
  const e = new Error(message);
  e.code = 'QLAUNCH_INVALID_LAUNCH';
  throw e;
}

function verifiedPrior(envelope, what) {
  const p = F.parse(envelope);
  if (p.signerId !== F.keyIdOf(p.publicKey)) badLaunch('the ' + what + ' names a signer id that does not match its public key');
  if (!native.verify(p.publicKey, F.encoded(p), p.signature)) badLaunch('the ' + what + ' signature does not verify');
  return p;
}

function manifest(options) {
  if (!options || typeof options !== 'object') F.reject('manifest needs options');
  options = own(options);
  requireSeed(options.key);
  if (options.vehicle === undefined) F.reject('vehicle is required, the launch vehicle');
  if (options.pad === undefined) F.reject('pad is required, the launch pad');
  if (options.scheduledAt === undefined) F.reject('scheduledAt is required, the scheduled liftoff time');
  return seal('manifest', options.key, {
    launchId: randomHex(16),
    vehicle: options.vehicle,
    pad: options.pad,
    scheduledAt: options.scheduledAt,
    operatorKeyId: keyId(options.key),
    operatorLabel: options.operatorLabel === undefined ? '' : options.operatorLabel,
    manifestedAt: options.manifestedAt === undefined ? nowIso() : options.manifestedAt,
    note: options.note === undefined ? '' : options.note,
  });
}

function license(options) {
  if (!options || typeof options !== 'object') F.reject('license needs options');
  options = own(options);
  requireSeed(options.key);
  if (options.manifest === undefined) F.reject('the manifest envelope the license authorises is required');
  const m = verifiedPrior(options.manifest, 'manifest');
  if (m.type !== 'manifest') badLaunch('the referenced envelope is not a manifest');
  return seal('license', options.key, {
    launchId: m.statement.launchId,
    manifestRef: F.refOf(m),
    licenseId: randomHex(16),
    authorityKeyId: keyId(options.key),
    authorityLabel: options.authorityLabel === undefined ? '' : options.authorityLabel,
    licensedAt: options.licensedAt === undefined ? nowIso() : options.licensedAt,
    note: options.note === undefined ? '' : options.note,
  });
}

function liftoff(options) {
  if (!options || typeof options !== 'object') F.reject('liftoff needs options');
  options = own(options);
  requireSeed(options.key);
  if (options.record === undefined) F.reject('the prior launch envelope this liftoff follows is required');
  const prior = verifiedPrior(options.record, 'record');
  return seal('liftoff', options.key, {
    launchId: prior.statement.launchId,
    priorRef: F.refOf(prior),
    providerKeyId: keyId(options.key),
    providerLabel: options.providerLabel === undefined ? '' : options.providerLabel,
    liftoffAt: options.liftoffAt === undefined ? nowIso() : options.liftoffAt,
    note: options.note === undefined ? '' : options.note,
  });
}

function deploy(options) {
  if (!options || typeof options !== 'object') F.reject('deploy needs options');
  options = own(options);
  requireSeed(options.key);
  if (options.record === undefined) F.reject('the prior launch envelope this deployment follows is required');
  if (options.payloadName === undefined) F.reject('payloadName is required, the payload that separated');
  if (options.slot === undefined) F.reject('slot is required, the deployment slot number');
  const prior = verifiedPrior(options.record, 'record');
  return seal('deploy', options.key, {
    launchId: prior.statement.launchId,
    priorRef: F.refOf(prior),
    payloadName: options.payloadName,
    slot: options.slot,
    controllerKeyId: keyId(options.key),
    controllerLabel: options.controllerLabel === undefined ? '' : options.controllerLabel,
    deployedAt: options.deployedAt === undefined ? nowIso() : options.deployedAt,
    note: options.note === undefined ? '' : options.note,
  });
}

function outcome(options) {
  if (!options || typeof options !== 'object') F.reject('outcome needs options');
  options = own(options);
  requireSeed(options.key);
  if (options.record === undefined) F.reject('the prior launch envelope this outcome follows is required');
  if (options.result === undefined) F.reject('result is required, one of ' + F.RESULTS.join(', '));
  const prior = verifiedPrior(options.record, 'record');
  return seal('outcome', options.key, {
    launchId: prior.statement.launchId,
    priorRef: F.refOf(prior),
    result: options.result,
    reporterKeyId: keyId(options.key),
    reporterLabel: options.reporterLabel === undefined ? '' : options.reporterLabel,
    reportedAt: options.reportedAt === undefined ? nowIso() : options.reportedAt,
    note: options.note === undefined ? '' : options.note,
  });
}

const ENDPOINT_OPTIONS = ['network', 'rpc', 'client', 'clients', 'trustSingleEndpoint', 'trustCustomEndpoints', 'allowLoopback', 'endpointAllowList', 'clockSlackMs'];

function strictOf(opts) {
  if (opts.strict === undefined) return true;
  if (typeof opts.strict !== 'boolean') F.reject('strict is true or false');
  return opts.strict;
}

function endpointOptions(opts) {
  const out = Object.create(null);
  for (const k of ENDPOINT_OPTIONS) if (opts[k] !== undefined) out[k] = opts[k];
  return out;
}

async function chainClock(opts, strict) {
  if (strict !== false && strictOf(opts) && opts.trustSingleEndpoint === true) {
    F.reject('strict mode takes the time of the chain only from at least two independent endpoints and refuses trustSingleEndpoint, set strict to false to rely on one endpoint');
  }
  try {
    return await qstamp.chainTime(endpointOptions(opts));
  } catch (e) {
    const err = new Error('the chain time could not be established, so no decision was made, ' + ((e && e.message) || 'unknown error'));
    err.code = 'QLAUNCH_NO_CHAIN_TIME';
    throw err;
  }
}

function anchorBatch(envelopes) {
  const list = Array.isArray(envelopes) ? envelopes : [envelopes];
  if (list.length === 0) F.reject('anchor needs at least one envelope');
  const parsed = list.map((e) => {
    const p = F.parse(e);
    if (p.anchor !== undefined) F.reject('an envelope is already anchored');
    if (p.signerId !== F.keyIdOf(p.publicKey)) F.reject('an envelope names a signer id that does not match its public key');
    if (!native.verify(p.publicKey, F.encoded(p), p.signature)) F.reject('an envelope carries a signature that does not verify');
    return p;
  });
  return { list, parsed };
}

function attach(list, receipts) {
  if (!Array.isArray(receipts) || receipts.length !== list.length) throw new Error('the anchoring returned an unexpected number of receipts');
  return list.map((e, i) => Object.assign({}, e, { anchor: receipts[i] }));
}

async function anchor(envelopes, options) {
  if (!options || typeof options !== 'object') F.reject('anchor needs the stamping options of a funded Quantova account');
  options = own(options);
  const { list, parsed } = anchorBatch(envelopes);
  const records = parsed.map((p) => ({ alg: 'sha3-256', digest: F.anchorDigest(p) }));
  const stampOptions = Object.assign(own(options), { records, kind: F.KIND });
  delete stampOptions.strict;
  return attach(list, await qstamp.stamp(stampOptions));
}

async function complete(envelopes, pending, options) {
  const opts = own(options);
  const plain = (Array.isArray(envelopes) ? envelopes : [envelopes]).map((e) => {
    let c;
    try {
      c = F.plainCopy(e);
    } catch (err) {
      return F.reject('an envelope is not plain data');
    }
    if (c && typeof c === 'object' && !Array.isArray(c)) delete c.anchor;
    return c;
  });
  const { list, parsed } = anchorBatch(plain);
  let p;
  try {
    p = F.plainCopy(pending);
  } catch (e) {
    F.reject('the pending stamp is not plain data');
  }
  if (!p || typeof p !== 'object' || !Array.isArray(p.records) || p.records.length !== parsed.length || String(p.kind) !== String(F.KIND)) {
    F.reject('the pending stamp does not belong to these envelopes');
  }
  parsed.forEach((c, i) => {
    const r = p.records[i];
    if (!r || r.alg !== 'sha3-256' || r.digest !== F.anchorDigest(c).toString('hex')) F.reject('the pending stamp does not belong to these envelopes, or they are in another order');
  });
  const completeOptions = own(opts);
  delete completeOptions.strict;
  return attach(list, await qstamp.complete(p, completeOptions));
}

const OPTIONS_OF = {
  manifest: ['key', 'vehicle', 'pad', 'scheduledAt', 'operatorLabel', 'manifestedAt', 'note'],
  license: ['key', 'manifest', 'authorityLabel', 'licensedAt', 'note'],
  liftoff: ['key', 'record', 'providerLabel', 'liftoffAt', 'note'],
  deploy: ['key', 'record', 'payloadName', 'slot', 'controllerLabel', 'deployedAt', 'note'],
  outcome: ['key', 'record', 'result', 'reporterLabel', 'reportedAt', 'note'],
  anchor: ['allowLoopback', 'client', 'clients', 'clockSlackMs', 'endpointAllowList', 'index', 'maxFee', 'meter', 'network', 'onPending', 'rpc', 'seed', 'signal', 'strict', 'timeoutMs', 'trustCustomEndpoints', 'trustSingleEndpoint'],
};

function onlyKnown(name, options) {
  if (options === null || typeof options !== 'object' || Array.isArray(options) || ArrayBuffer.isView(options)) return;
  const unknown = Object.keys(options).find((k) => !OPTIONS_OF[name].includes(k));
  if (unknown !== undefined) F.reject('the option ' + unknown.replace(/[^A-Za-z0-9_]/g, '?').slice(0, 40) + ' is not an option of ' + name + ', so nothing was signed');
}

function strict(name, fn, at, isAsync) {
  return function strictly(...args) {
    try {
      onlyKnown(name, args[at]);
    } catch (e) {
      if (isAsync) return Promise.reject(e);
      throw e;
    }
    return fn.apply(this, args);
  };
}

module.exports = {
  own, generateKey, publicKey, keyId, describeKey, launchRef, verifiedPrior, anchor, complete, chainClock, endpointOptions, strictOf,
};
Object.assign(module.exports, {
  manifest: strict('manifest', manifest, 0, false),
  license: strict('license', license, 0, false),
  liftoff: strict('liftoff', liftoff, 0, false),
  deploy: strict('deploy', deploy, 0, false),
  outcome: strict('outcome', outcome, 0, false),
});
