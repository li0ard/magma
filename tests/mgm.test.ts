import { describe, test, expect } from "bun:test"
import { decryptMGM, encryptMGM } from "../src/"

const key = Buffer.from("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", "hex")
const iv = Buffer.from("12DEF06B3C130A59", "hex")
const ad = Buffer.from("01010101010101010202020202020202030303030303030304040404040404040505050505050505EA", "hex")
const plaintext = Buffer.from("FFEEDDCCBBAA998811223344556677008899AABBCCEEFF0A001122334455667799AABBCCEEFF0A001122334455667788AABBCCEEFF0A00112233445566778899AABBCC", "hex")
const encrypted = Buffer.from("C795066C5F9EA03B85113342459185AE1F2E00D6BF2B785D940470B8BB9C8E7D9A5DD3731F7DDC70EC27CB0ACE6FA57670F65C646ABB75D547AA37C3BCB5C34E03BB9CA7928069AA10FD10", "hex")

describe("MGM", () => {
    test("Encryption", () => {
        let result = encryptMGM(key, plaintext, iv, ad)
        expect(result).toStrictEqual(encrypted)
    })

    test("Decryption", () => {
        let result = decryptMGM(key, encrypted, iv, ad)
        expect(result).toStrictEqual(plaintext)
    })
})