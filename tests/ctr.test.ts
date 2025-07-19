import { describe, test, expect } from "bun:test"
import { decryptCTR, encryptCTR, sboxes } from "../src"

describe("CTR", () => {
    const key = Buffer.from("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", "hex")
    const iv = Buffer.from("1234567890abcdef234567890abcdef134567890abcdef12", "hex")
    const plaintext = Buffer.from("92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41", "hex")
    const encrypted = Buffer.from("4e98110c97b7b93c3e250d93d6e85d69136d868807b2dbef568eb680ab52a12d", "hex")
    test("Encryption", () => {
        let result = encryptCTR(key, plaintext, iv.subarray(0, 4))
        expect(result).toStrictEqual(encrypted)
    })

    test("Decryption", () => {
        let result = decryptCTR(key, encrypted, iv.subarray(0, 4))
        expect(result).toStrictEqual(plaintext)
    })
})

describe("CTR (GOST 28147-89)", () => {
    const key = Buffer.from("0475f6e05038fbfad2c7c390edb3ca3d1547124291ae1e8a2f79cd9ed2bcefbd", "hex")
    const iv = Buffer.from("0201010101010101", "hex")
    const plaintext = Buffer.from("07060504030201000f0e0d0c0b0a090817161514131211101f1e1d1c1b1a191827262524232221202f2e2d2c2b2a292837363534333231303f3e3d3c3b3a393847464544434241404f4e4d4c4b4a494857565554535251505f5e5d5c5b5a595867666564636261606f6e6d6c6b6a696877767574737271707f7e7d7c7b7a797887868584838281808f8e8d8c8b8a898897969594939291909f9e9d9c9b9a9998a7a6a5a4a3a2a1a0afaeadacabaaa9a8b7b6b5b4b3b2b1b0bfbebdbcbbbab9b8c7c6c5c4c3c2c1c0cfcecdcccbcac9c8d7d6d5d4d3d2d1d0dfdedddcdbdad9d8e7e6e5e4e3e2e1e0efeeedecebeae9e8f7f6f5f4f3f2f1f0fffefdfcfb", "hex")
    const encrypted = Buffer.from("4a5e376ca112d35509131a21acfbb21e8c249b57206846d5232a263512565c692a2fd1abbd45dc3a1aa45764d5e4696db48bf154783b108f7a4b32e0e84cbf032437956a55a8ce6f956212f679e6f01b86ef363605d86f10a1410507f8faa40b172c71bc8bcbcf3d7418320b1cd29e75ba3e61e16196d0ee8ff29a5eb77a15aa4e1e777c99e14113f46039464c35de95cc4fd5afd14d841a45c72af22cc0b794a308b91296b597993ab70c1456b9cb4944a993a9fb19108c6a68e87b0657f0ef8844a6d298bed407413745a6713676694b75153390296e33cb963978192e96f3494c893da1868200cebd542965001d1613c3fe1f8c5563091fcdd428ca", "hex")

    test("Encryption", () => {
        let result = encryptCTR(key, plaintext, iv, true, sboxes.ID_GOST_28147_89_TEST_PARAM_SET)
        expect(result).toStrictEqual(encrypted)
    })

    test("Decryption", () => {
        let result = encryptCTR(key, encrypted, iv, true, sboxes.ID_GOST_28147_89_TEST_PARAM_SET)
        expect(result).toStrictEqual(plaintext)
    })
})