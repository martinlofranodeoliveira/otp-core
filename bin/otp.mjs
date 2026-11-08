#!/usr/bin/env node
// Demo: RFC 4226 counters 0-2, asserts exact codes. --assert exits non-zero on mismatch.
import { hotp } from '../src/otp.mjs';

const SECRET = '12345678901234567890';
const CASES = [[0, '755224'], [1, '287082'], [9, '520489']];

let failed = 0;
for (const [counter, expected] of CASES) {
  const got = hotp(SECRET, counter);
  const pass = got === expected;
  if (!pass) failed++;
  console.log(`${pass ? 'PASS' : 'FAIL'} counter ${counter} -> ${got}`);
}
if (process.argv.includes('--assert') && failed > 0) process.exit(1);
if (failed > 0) process.exitCode = 1;
console.log(failed === 0 ? 'demo: all cases as expected' : `demo: ${failed} mismatch(es)`);
