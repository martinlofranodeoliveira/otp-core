// SPDX-License-Identifier: MIT
// HOTP (RFC 4226) and TOTP (RFC 6238, SHA-1) generation and verification.
// Secrets are caller-supplied bytes; the library reads no clock for HOTP
// (TOTP takes an explicit unix time). No network, no I/O.

import { createHmac, timingSafeEqual } from 'node:crypto';

export const MAX_DIGITS = 10;

export class OtpError extends Error {
  constructor(code, detail = '') {
    super(detail ? `${code}: ${detail}` : code);
    this.name = 'OtpError';
    this.code = code;
  }
}

function secretBytes(secret) {
  if (typeof secret === 'string') return new TextEncoder().encode(secret);
  if (secret instanceof Uint8Array) return secret;
  throw new OtpError('BAD_SECRET');
}

function counterBuffer(counter) {
  const c = typeof counter === 'bigint' ? counter : BigInt(counter);
  if (c < 0n) throw new OtpError('BAD_COUNTER');
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(c);
  return buf;
}

/** HOTP value with `digits` (6-10). Returns zero-padded string. */
export function hotp(secret, counter, digits = 6) {
  if (!Number.isInteger(digits) || digits < 6 || digits > MAX_DIGITS) throw new OtpError('BAD_DIGITS');
  const mac = createHmac('sha1', Buffer.from(secretBytes(secret))).update(counterBuffer(counter)).digest();
  const offset = mac[mac.length - 1] & 0x0f;
  const code = ((mac[offset] & 0x7f) * 2 ** 24 + mac[offset + 1] * 2 ** 16 + mac[offset + 2] * 2 ** 8 + mac[offset + 3]) % 10 ** digits;
  return String(code).padStart(digits, '0');
}

/** TOTP value at unixSec with step (default 30s). */
export function totp(secret, unixSec, step = 30, digits = 6) {
  if (typeof unixSec !== 'number' || !Number.isFinite(unixSec) || unixSec < 0) throw new OtpError('BAD_TIME');
  if (!Number.isInteger(step) || step <= 0) throw new OtpError('BAD_STEP');
  return hotp(secret, BigInt(Math.floor(unixSec / step)), digits);
}

/** Constant-time comparison of codes. */
function same(a, b) {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}

/** True when code matches counter within ±window. */
export function verifyHotp(secret, code, counter, window = 1, digits = 6) {
  if (typeof code !== 'string') throw new OtpError('BAD_CODE');
  if (!Number.isInteger(window) || window < 0 || window > 100) throw new OtpError('BAD_WINDOW');
  const c = BigInt(counter);
  for (let d = -BigInt(window); d <= BigInt(window); d++) {
    if (c + d < 0n) continue;
    if (same(hotp(secret, c + d, digits), code)) return true;
  }
  return false;
}

/** True when code matches at unixSec within ±skew steps. */
export function verifyTotp(secret, code, unixSec, step = 30, digits = 6, skew = 1) {
  if (!Number.isInteger(skew) || skew < 0 || skew > 100) throw new OtpError('BAD_WINDOW');
  const center = Math.floor(unixSec / step);
  for (let d = -skew; d <= skew; d++) {
    if (center + d < 0) continue;
    if (same(totp(secret, (center + d) * step, step, digits), code)) return true;
  }
  return false;
}
