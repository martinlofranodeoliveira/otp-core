# Contract — otp-core

ESM in `src/otp.mjs`, only `node:crypto` (HMAC-SHA1, `timingSafeEqual`,
`randomUUID`-free). No network, no I/O, no clock reads — TOTP takes an
explicit unix time.

| Export | Result |
| --- | --- |
| `MAX_DIGITS` (10) | Hard bound. |
| `hotp(secret, counter, digits=6)` | Zero-padded string. Counter number\|bigint. |
| `totp(secret, unixSec, step=30, digits=6)` | `hotp` at `floor(unixSec/step)`. |
| `verifyHotp(secret, code, counter, window=1)` | Constant-time compare across ±window. |
| `verifyTotp(secret, code, unixSec, step, digits, skew=1)` | Same across ±skew steps. |

Errors: `BAD_SECRET` · `BAD_COUNTER` · `BAD_DIGITS` · `BAD_TIME` ·
`BAD_STEP` · `BAD_CODE` · `BAD_WINDOW`.
