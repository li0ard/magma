<p align="center">
    <b>@li0ard/magma</b><br>
    <b>Magma cipher implementation in pure TypeScript</b>
    <br>
    <a href="https://li0ard.is-cool.dev/magma">docs</a>
    <br><br>
    <a href="https://github.com/li0ard/magma/actions/workflows/test.yml"><img src="https://github.com/li0ard/magma/actions/workflows/test.yml/badge.svg" /></a>
    <a href="https://github.com/li0ard/magma/blob/main/LICENSE"><img src="https://img.shields.io/github/license/li0ard/magma" /></a>
    <br>
    <a href="https://npmjs.com/package/@li0ard/magma"><img src="https://img.shields.io/npm/v/@li0ard/magma" /></a>
    <a href="https://jsr.io/@li0ard/magma"><img src="https://jsr.io/badges/@li0ard/magma" /></a>
    <br>
    <hr>
</p>

> [!WARNING]
> This library is currently in alpha stage: the lib is not very stable yet, and there may be a lot of bugs
> feel free to try it out, though, any feedback is appreciated!

## Installation

```bash
# from NPM
npm i @li0ard/magma

# from JSR
bunx jsr i @li0ard/magma
```

## Supported modes (GOST R 34.12-2015)
- [x] Electronic Codebook (ECB)
- [x] Cipher Block Chaining (CBC)
- [x] Cipher Feedback (CFB)
- [x] Counter (CTR)
- [x] Output Feedback (OFB)
- [x] MAC (CMAC/OMAC/OMAC1)
- [x] Counter with Advance Cryptographic Prolongation of Key Material (CTR-ACPKM)
- [x] MAC with Advance Cryptographic Prolongation of Key Material (OMAC-ACPKM)
- [x] Multilinear Galois Mode (MGM)

## Supported modes (GOST 28147-89)
- [x] Electronic Codebook (ECB)
- [x] Cipher Block Chaining (CBC)
- [x] Cipher Feedback (CFB)
- [x] Counter (CTR)
- [ ] *MAC (Soon...)*

## Features
- Provides simple and modern API
- Most of the APIs are strictly typed
- Fully complies with [GOST R 34.12-2015 (RFC 8891)](https://datatracker.ietf.org/doc/html/rfc8891), [GOST R 34.13-2015 (in Russian)](https://tc26.ru/standard/gost/GOST_R_3413-2015.pdf) and [GOST 28147-89 (in Russian)](https://meganorm.ru/Data2/1/4294826/4294826631.pdf) standarts
- Supports Bun, Node.js, Deno, Browsers

## Examples
### ECB mode
```ts
import { decryptECB, encryptECB } from "@li0ard/magma";

const key = Buffer.from("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", "hex")
const plaintext = Buffer.from("fedcba9876543210", "hex")
const encrypted = encryptECB(key, plaintext)
console.log(encrypted) // Uint8Array [ ... ]

const decrypted = decryptECB(key, encrypted)
console.log(decrypted) // Uint8Array [ ... ]
```

### CTR-ACPKM mode
```ts
import { decryptCTR_ACPKM, encryptCTR_ACPKM } from "@li0ard/magma"

const key = Buffer.from("8899AABBCCDDEEFF0011223344556677FEDCBA98765432100123456789ABCDEF", "hex")
const iv = Buffer.from("12345678", "hex")
const plaintext = Buffer.from("1122334455667700FFEEDDCCBBAA998800112233445566778899AABBCCEEFF0A112233445566778899AABBCCEEFF0A002233445566778899", "hex")

const encrypted = encryptCTR_ACPKM(key, plaintext, iv)
console.log(encrypted) // Uint8Array [...]

const decrypted = decryptCTR_ACPKM(key, encrypted, iv)
console.log(decrypted) // Uint8Array [...]
```

### ECB mode (GOST 28147-89)
```ts
import { decryptECB, encryptECB, sboxes } from "@li0ard/magma";

const key = Buffer.from("0475f6e05038fbfad2c7c390edb3ca3d1547124291ae1e8a2f79cd9ed2bcefbd", "hex")
const plaintext = Buffer.from("07060504030201000f0e0d0c0b0a090817161514131211101f1e1d1c1b1a191827262524232221202f2e2d2c2b2a292837363534333231303f3e3d3c3b3a393847464544434241404f4e4d4c4b4a494857565554535251505f5e5d5c5b5a595867666564636261606f6e6d6c6b6a696877767574737271707f7e7d7c7b7a797887868584838281808f8e8d8c8b8a898897969594939291909f9e9d9c9b9a9998a7a6a5a4a3a2a1a0afaeadacabaaa9a8b7b6b5b4b3b2b1b0bfbebdbcbbbab9b8c7c6c5c4c3c2c1c0cfcecdcccbcac9c8d7d6d5d4d3d2d1d0dfdedddcdbdad9d8e7e6e5e4e3e2e1e0efeeedecebeae9e8f7f6f5f4f3f2f1f0fffefdfcfbfaf9f8", "hex")
const encrypted = encryptECB(key, plaintext, true, sboxes.ID_GOST_28147_89_TEST_PARAM_SET)
console.log(encrypted) // Uint8Array [ ... ]

const decrypted = decryptECB(key, encrypted, true, sboxes.ID_GOST_28147_89_TEST_PARAM_SET)
console.log(decrypted) // Uint8Array [ ... ]
```