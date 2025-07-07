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

## Supported modes
- [x] Electronic Codebook (ECB)
- [x] Cipher Block Chaining (CBC)
- [x] Cipher Feedback (CFB)
- [x] Counter (CTR)
- [x] Output Feedback (OFB)
- [x] MAC (CMAC/OMAC/OMAC1)
- [x] Counter with Advance Cryptographic Prolongation of Key Material (CTR-ACPKM)
- [x] MAC with Advance Cryptographic Prolongation of Key Material (OMAC-ACPKM)
- [ ] *Multilinear Galois Mode (MGM) (Soon)*

## Features
- Provides simple and modern API
- Most of the APIs are strictly typed
- Fully complies with [GOST R 34.12-2015 (RFC 8891)](https://datatracker.ietf.org/doc/html/rfc8891) and [GOST R 34.13-2015 (in Russian)](https://tc26.ru/standard/gost/GOST_R_3413-2015.pdf) standarts
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