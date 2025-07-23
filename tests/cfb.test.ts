import { describe, test, expect } from "bun:test"
import { encryptCFB, decryptCFB, sboxes } from "../src/";

describe("CFB", () => {
    const key = Buffer.from("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", "hex")
    const iv = Buffer.from("1234567890abcdef234567890abcdef134567890abcdef12", "hex")
    const plaintext = Buffer.from("92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41", "hex")
    const encrypted = Buffer.from("db37e0e266903c830d46644c1f9a089c24bdd2035315d38bbcc0321421075505", "hex")
    test("Encryption", () => {
        expect(encryptCFB(key, plaintext, iv.subarray(0, 16))).toStrictEqual(encrypted)
    })

    test("Decryption", () => {
        expect(decryptCFB(key, encrypted, iv.subarray(0, 16))).toStrictEqual(plaintext)
    })
})

describe("CFB (GOST 28147-89)", () => {
    const key = Buffer.from("75713134B60FEC45A607BB83AA3746AF4FF99DA6D1B53B5B1B402A1BAA030D1B", "hex")
    const iv = Buffer.from("0102030405060708", "hex")
    const plaintext = Buffer.from("112233445566778899AABBCCDD800000", "hex")
    const encrypted = Buffer.from("6EE84586DD2BCA0CAD3616940E164242", "hex")

    test("Encryption", () => {
        expect(encryptCFB(key, plaintext, iv, true, sboxes.ID_GOSTR_3411_94_TEST_PARAM_SET)).toStrictEqual(encrypted)
    })

    test("Decryption", () => {
        expect(decryptCFB(key, encrypted, iv, true, sboxes.ID_GOSTR_3411_94_TEST_PARAM_SET)).toStrictEqual(plaintext)
    })
})