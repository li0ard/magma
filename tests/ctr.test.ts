import { describe, test, expect } from "bun:test"
import { decryptCTR, encryptCTR } from "../src"

const key = Buffer.from("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", "hex")
const iv = Buffer.from("1234567890abcdef234567890abcdef134567890abcdef12", "hex")
const plaintext = Buffer.from("92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41", "hex")
const encrypted = Buffer.from("4e98110c97b7b93c3e250d93d6e85d69136d868807b2dbef568eb680ab52a12d", "hex")

describe("CTR", () => {
    test("Encryption", () => {
        let result = encryptCTR(key, plaintext, iv.subarray(0, 4))
        expect(result).toStrictEqual(encrypted)
    })

    test("Decryption", () => {
        let result = decryptCTR(key, encrypted, iv.subarray(0, 4))
        expect(result).toStrictEqual(plaintext)
    })
})