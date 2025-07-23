import { describe, test, expect } from "bun:test"
import { encryptCBC, decryptCBC, sboxes } from "../src/";

describe("CBC", () => {
    const key = Buffer.from("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", "hex")
    const iv = Buffer.from("1234567890abcdef234567890abcdef134567890abcdef12", "hex")
    const plaintext = Buffer.from("92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41", "hex")
    const encrypted = Buffer.from("96d1b05eea683919aff76129abb937b95058b4a1c4bc001920b78b1a7cd7e667", "hex")
    test("Encryption", () => {
        expect(encryptCBC(key, plaintext, iv)).toStrictEqual(encrypted)
    })

    test("Decryption", () => {
        expect(decryptCBC(key, encrypted, iv)).toStrictEqual(plaintext)
    })
})

describe("CBC (GOST 28147-89)", () => {
    const key = Buffer.from("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", "hex")
    const iv = Buffer.from("1234567890abcdef234567890abcdef134567890abcdef12", "hex")
    const plaintext = Buffer.from("92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41", "hex")
    const encrypted = Buffer.from("cf9506a890323fd327dbf50b065dffbdd7fcb975b73b0dd83de52fb6c1a0eb1f", "hex")

    test("Encryption", () => {
        expect(encryptCBC(key, plaintext, iv, true, sboxes.ID_GOST_28147_89_TEST_PARAM_SET)).toStrictEqual(encrypted)
    })

    test("Decryption", () => {
        expect(decryptCBC(key, encrypted, iv, true, sboxes.ID_GOST_28147_89_TEST_PARAM_SET)).toStrictEqual(plaintext)
    })
})