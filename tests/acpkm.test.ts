import { describe, test, expect } from "bun:test"
import { decryptCTR_ACPKM, encryptCTR_ACPKM, acpkmDerivation, acpkmDerivationMaster, omac_ACPKM } from "../src"

const key = Buffer.from("8899AABBCCDDEEFF0011223344556677FEDCBA98765432100123456789ABCDEF", "hex")
const iv = Buffer.from("12345678", "hex")
const plaintext = Buffer.from("1122334455667700FFEEDDCCBBAA998800112233445566778899AABBCCEEFF0A112233445566778899AABBCCEEFF0A002233445566778899", "hex")
const encrypted = Buffer.from("2AB81DEEEB1E4CAB68E104C4BD6B94EAC72C67AF6C2E5B6B0EAFB61770F1B32EA1AE71149EED1382ABD467180672EC6F84A2F15B3FCA72C1", "hex")

describe("CTR-ACPKM", () => {
    test("Derivation", () => {
        let expected1 = Buffer.from("863EA017842C3D372B18A85A28E2317D74BEFC107720DE0C9E8AB974ABD00CA0", "hex")
        let expected2 = Buffer.from("49A5E2677DE555982B8AD5E826652D17EEC847BF5B3997A81CF7FE7F1187BD27", "hex")
        let expected3 = Buffer.from("3256BF3F97B5667426A9FB1C5EAABE41893CCDD5A868F9B63B0AA90720FA43C4", "hex")

        let result1 = acpkmDerivation(key)
        let result2 = acpkmDerivation(result1)
        let result3 = acpkmDerivation(result2)

        expect(result1).toStrictEqual(expected1)
        expect(result2).toStrictEqual(expected2)
        expect(result3).toStrictEqual(expected3)
    })
    test("Encryption", () => {
        let result = encryptCTR_ACPKM(key, plaintext, iv)
        expect(result).toStrictEqual(encrypted)
    })

    test("Decryption", () => {
        let result = decryptCTR_ACPKM(key, encrypted, iv)
        expect(result).toStrictEqual(plaintext)
    })
})

describe("OMAC-ACPKM", () => {
    let expected = Buffer.from("0DF2F5273DA328932AC49D81D36B2558A50DBF9BBCAC74A614B2CCB2F1CBCD8A70638E3DE8B3571E8D3826D55E63A167E2406640547B9F1F5F2B43612AAEAFDA180BAC8604DFA6FE53C2CE270E9C9F5268D0FDBFE1A3BDD9BE5B96D0A12023486EF1710F924AE0313052CB5FCA0B791E1BABE8576D0FE3A8", "hex")
    test("Derivation", () => {
        let result = acpkmDerivationMaster(key, 1)
        expect(result).toStrictEqual(expected.subarray(0, 40))
    })

    test("Derivation #2", () => {
        let result = acpkmDerivationMaster(key, 3)
        expect(result).toStrictEqual(expected)
    })

    test("Compute", () => {
        let data = Buffer.from("1122334455667700FFEEDDCC", "hex")
        let expected = Buffer.from("A0540E3730ACBCF3", "hex")
        let result = omac_ACPKM(key, data)
        expect(result).toStrictEqual(expected)
    })

    test("Compute #2", () => {
        let data = Buffer.from("1122334455667700FFEEDDCCBBAA998800112233445566778899AABBCCEEFF0A1122334455667788", "hex")
        let expected = Buffer.from("34008DAD5496BB8E", "hex")
        let result = omac_ACPKM(key, data)
        expect(result).toStrictEqual(expected)
    })
})