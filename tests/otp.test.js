import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { hotp, totp, verifyHotp, verifyTotp, OtpError } from '../src/otp.mjs';

// RFC 4226 Appendix D secret (ASCII) and expected 6-digit values.
const SECRET = '12345678901234567890';
const RFC4226 = ['755224', '287082', '359152', '969429', '338314', '254676', '287922', '162583', '399871', '520489'];

describe('HOTP (RFC 4226 vectors)', () => {
  it('matches all 10 appendix vectors', () => {
    RFC4226.forEach((expected, counter) => {
      assert.equal(hotp(SECRET, counter), expected, `counter ${counter}`);
    });
  });
  it('verifies with resync window', () => {
    assert.equal(verifyHotp(SECRET, '359152', 0, 2), true);
    assert.equal(verifyHotp(SECRET, '359152', 0, 1), false);
    assert.throws(() => verifyHotp(SECRET, 42, 0), (e) => e.code === 'BAD_CODE');
  });
});

describe('TOTP (RFC 6238 SHA-1 spot checks)', () => {
  it('matches known time/code pairs', () => {
    assert.equal(totp(SECRET, 59), '287082');
    assert.equal(totp(SECRET, 1111111109), '081804');
    assert.equal(totp(SECRET, 59, 30, 8), '94287082');
  });
  it('verifies with skew, rejects drift', () => {
    assert.equal(verifyTotp(SECRET, totp(SECRET, 59), 59 + 29), true);
    assert.equal(verifyTotp(SECRET, totp(SECRET, 59), 59 + 61, 30, 6, 0), false);
  });
  it('rejects bad input', () => {
    assert.throws(() => hotp(SECRET, 0, 5), (e) => e.code === 'BAD_DIGITS');
    assert.throws(() => totp(SECRET, -1), (e) => e.code === 'BAD_TIME');
    assert.ok(new OtpError('X') instanceof Error);
  });
});
