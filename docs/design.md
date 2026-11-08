# Design — otp-core

Dynamic truncation per RFC 4226 §5.4; TOTP is HOTP over the time
counter per RFC 6238 (SHA-1 only — SHA-256/512 suites out of scope).
Verification compares in constant time and never reveals which side
of the window matched.

Oracle: all ten RFC 4226 appendix-D vectors, RFC 6238 SHA-1 spot
checks (59s, 1111111109s, 8-digit form), resync/skew boundaries.
Secrets stay caller-owned buffers; nothing is persisted or logged.
