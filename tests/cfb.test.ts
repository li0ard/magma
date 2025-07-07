import { describe, test, expect } from "bun:test"
import { encryptCFB, decryptCFB } from "../src/";

const key = Buffer.from("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", "hex")
const iv = Buffer.from("1234567890abcdef234567890abcdef134567890abcdef12", "hex")
const plaintext = Buffer.from("92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41", "hex")
const encrypted = Buffer.from("db37e0e266903c830d46644c1f9a089c24bdd2035315d38bbcc0321421075505", "hex")

describe("CFB", () => {
    test("Encryption", () => {
        let result = encryptCFB(key, plaintext, iv.subarray(0, 16))
        expect(result).toStrictEqual(encrypted)
    })

    test("Decryption", () => {
        let result = decryptCFB(key, encrypted, iv.subarray(0, 16))
        expect(result).toStrictEqual(plaintext)
    })
})