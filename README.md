# QLaunch

QLaunch is a live production post quantum launch and payload manifest record tool for space launch on the Quantova network. It proves the manifest, license, liftoff, payload deployment and outcome of a launch, and it lets any third party confirm that history without trusting the party that created it.

QLaunch proves records without disclosing them. Launch identities and operational details stay private on the systems of the party that holds them. Only a salted cryptographic commitment is written to the chain, and no sensitive detail is ever published.

## What it records

Each record is a signed envelope of one of five types.

1. manifest, a launch operator declares the vehicle, pad and scheduled liftoff of a launch.
2. license, a launch authority licenses the manifested launch.
3. liftoff, the provider records the liftoff.
4. deploy, a controller records a payload separation at a stated slot.
5. outcome, a reporter records the final result of the launch.

Every record is signed with ML-DSA-65 under FIPS 204 by the party whose role it names, and each later record links to the one before it so the whole life of a launch forms a chain.

## Proving the time

A record on its own carries only the claim of its signer. Anchoring a record on the Quantova network through Qstamp adds a post quantum evidence anchor that fixes the latest moment the record existed, provable against the record and the signer by anyone, without claiming a regulated timestamp status that Quantova Inc does not hold.

## Install

```
npm install @quantovainc/qlaunch
```

## Use

```js
const qlaunch = require('@quantovainc/qlaunch');

const operator = qlaunch.generateKey();
const flight = qlaunch.manifest({
  key: operator,
  vehicle: 'Quantova Heavy',
  pad: 'LC 39A',
  scheduledAt: '2026-12-01T12:00:00.000Z',
  operatorLabel: 'Quantova Launch',
});

const anchored = await qlaunch.anchor(flight, { seed, index: 0, network: 'testnet' });
const result = await qlaunch.verify(anchored[0], { type: 'manifest', network: 'testnet' });
```

## What a record does not establish

1. It does not show that the stated facts are true. It shows only that the signer stated them and that the statement existed unchanged at a point in time.
2. It does not identify a natural or legal person. The signer is a chain address, and linking an address to an operator, authority or controller is a separate attestation.
3. The labels are text written by the signer, they are not a verified identity.

## License

Apache-2.0 OR MIT
