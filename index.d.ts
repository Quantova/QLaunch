// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

export type Result = 'success' | 'partial' | 'failure';
export type RecordType = 'manifest' | 'license' | 'liftoff' | 'deploy' | 'outcome';

export interface KeyDescription {
  format: 'qlaunch-key/1';
  algorithm: 'ML-DSA-65';
  id: string;
  publicKey: string;
}

export interface Signer {
  id: string;
  publicKey: string;
}

export interface Envelope<T = Record<string, unknown>> {
  format: 'qlaunch/1';
  type: RecordType;
  algorithm: 'ML-DSA-65';
  signer: Signer;
  statement: T;
  signature: string;
  anchor?: unknown;
}

export interface ManifestOptions {
  key: Uint8Array;
  vehicle: string;
  pad: string;
  scheduledAt: string;
  operatorLabel?: string;
  manifestedAt?: string;
  note?: string;
}

export interface LicenseOptions {
  key: Uint8Array;
  manifest: Envelope;
  authorityLabel?: string;
  licensedAt?: string;
  note?: string;
}

export interface LiftoffOptions {
  key: Uint8Array;
  record: Envelope;
  providerLabel?: string;
  liftoffAt?: string;
  note?: string;
}

export interface DeployOptions {
  key: Uint8Array;
  record: Envelope;
  payloadName: string;
  slot: number;
  controllerLabel?: string;
  deployedAt?: string;
  note?: string;
}

export interface OutcomeOptions {
  key: Uint8Array;
  record: Envelope;
  result: Result;
  reporterLabel?: string;
  reportedAt?: string;
  note?: string;
}

export interface AnchorOptions {
  seed?: Uint8Array;
  index?: number;
  network?: string;
  rpc?: string;
  clients?: unknown[];
  trustSingleEndpoint?: boolean;
  trustCustomEndpoints?: boolean;
  allowLoopback?: boolean;
  maxFee?: string | number | bigint;
  meter?: string | number | bigint;
  timeoutMs?: number;
  onPending?: (pending: unknown) => void;
  signal?: AbortSignal;
}

export interface VerifyOptions {
  type?: RecordType;
  prior?: Envelope;
  launchId?: string;
  signerKeyId?: string;
  signerPublicKey?: string | Uint8Array;
  network: string;
  strict?: boolean;
  requireAnchor?: boolean;
  maxAnchorDelay?: number;
  at?: string;
  deadlineMs?: number;
  rpc?: string;
  clients?: unknown[];
  trustSingleEndpoint?: boolean;
  trustCustomEndpoints?: boolean;
  allowLoopback?: boolean;
}

export interface Check {
  name: string;
  ok: boolean;
  detail: string;
  transport: boolean;
  indeterminate: boolean;
  unproven: boolean;
}

export interface VerifyResult {
  valid: boolean;
  status: 'valid' | 'unproven' | 'indeterminate' | 'invalid';
  type: RecordType | null;
  launchId?: string;
  signerId?: string;
  statement?: Record<string, unknown>;
  anchoredAt?: string | null;
  endpoints: string[];
  officialEndpoints: boolean | null;
  checks: Check[];
}

export function generateKey(): Uint8Array;
export function publicKey(key: Uint8Array): Uint8Array;
export function keyId(key: Uint8Array): string;
export function describeKey(key: Uint8Array): KeyDescription;
export function launchRef(secret: Uint8Array, reference: string): string;
export function manifest(options: ManifestOptions): Envelope;
export function license(options: LicenseOptions): Envelope;
export function liftoff(options: LiftoffOptions): Envelope;
export function deploy(options: DeployOptions): Envelope;
export function outcome(options: OutcomeOptions): Envelope;
export function anchor(envelopes: Envelope | Envelope[], options: AnchorOptions): Promise<Envelope[]>;
export function complete(envelopes: Envelope | Envelope[], pending: unknown, options?: AnchorOptions): Promise<Envelope[]>;
export function verify(envelope: Envelope, options: VerifyOptions): Promise<VerifyResult>;
export function anchorDigest(envelope: Envelope): string;
export function recordRef(envelope: Envelope): string;

export const FORMAT: 'qlaunch/1';
export const ALGORITHM: 'ML-DSA-65';
export const KIND: 1408;
export const TYPES: readonly RecordType[];
export const RESULTS: readonly Result[];
export const PUBLIC_KEY_BYTES: 1952;
export const SIGNATURE_BYTES: 3309;
