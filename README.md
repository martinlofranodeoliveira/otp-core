# otp-core

HOTP (RFC 4226) and TOTP (RFC 6238) generation and verification with
resync windows. Node crypto only, zero dependencies.

Part of the LOFRANO TECNOLOGIA open-source lab. MIT.

```js
import { hotp, verifyHotp } from './src/otp.mjs';
hotp('12345678901234567890', 1); // '287082'
```

```sh
npm test          # 5 tests incl. full RFC 4226 appendix, node:test
npm run demo
```

SHA-1 suites only; secrets never logged. MIT — see `LICENSE`.
[Versão em português](README.pt-BR.md).
