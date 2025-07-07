import { describe, test, expect } from "bun:test"
import { decryptECB, encryptECB } from "../src";

const key = Buffer.from("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", "hex")
const plaintext = Buffer.from("fedcba9876543210", "hex")
const encrypted = Buffer.from("4ee901e5c2d8ca3d", "hex")

describe("ECB", () => {
    test("Encryption", () => {
        let result = encryptECB(key, plaintext)
        expect(result).toStrictEqual(encrypted)
    })

    test("Decryption", () => {
        let result = decryptECB(key, encrypted)
        expect(result).toStrictEqual(plaintext)
    })
})