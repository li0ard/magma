import { describe, test, expect } from "bun:test"
import { decryptECB, encryptECB, sboxes } from "../src";

describe("ECB", () => {
    const key = Buffer.from("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", "hex")
    const plaintext = Buffer.from("fedcba9876543210", "hex")
    const encrypted = Buffer.from("4ee901e5c2d8ca3d", "hex")
    test("Encryption", () => {
        let result = encryptECB(key, plaintext)
        expect(result).toStrictEqual(encrypted)
    })

    test("Decryption", () => {
        let result = decryptECB(key, encrypted)
        expect(result).toStrictEqual(plaintext)
    })
})

describe("ECB (GOST 28147-89)", () => {
    const key = Buffer.from("0475f6e05038fbfad2c7c390edb3ca3d1547124291ae1e8a2f79cd9ed2bcefbd", "hex")
    const plaintext = Buffer.from("07060504030201000f0e0d0c0b0a090817161514131211101f1e1d1c1b1a191827262524232221202f2e2d2c2b2a292837363534333231303f3e3d3c3b3a393847464544434241404f4e4d4c4b4a494857565554535251505f5e5d5c5b5a595867666564636261606f6e6d6c6b6a696877767574737271707f7e7d7c7b7a797887868584838281808f8e8d8c8b8a898897969594939291909f9e9d9c9b9a9998a7a6a5a4a3a2a1a0afaeadacabaaa9a8b7b6b5b4b3b2b1b0bfbebdbcbbbab9b8c7c6c5c4c3c2c1c0cfcecdcccbcac9c8d7d6d5d4d3d2d1d0dfdedddcdbdad9d8e7e6e5e4e3e2e1e0efeeedecebeae9e8f7f6f5f4f3f2f1f0fffefdfcfbfaf9f8", "hex")
    const encrypted = Buffer.from("4b8c4c9815f24aea1ec35709b3bc2ed1e0d1f222652d5918f7dffc804bde5c6846537553a7460dec051f1bd30a631ab778c443e05d3ea40e2d7e23a91bc902bc210c84cb0d0a07c87bd0fbb51a14045ca25397712e5cc28f393f6f52f230264e8ce0d101756ddcd303791ecad5c10e12530a78e20ab11cea3af855b97ce10bbaa0c896eb505ad36043a30f98dbd9506d6391af0140e9755a465c1f194a0b899bc4f6f8f52f873ffa26d4f825ba1f9882fc26af2dc0f9c45849fa09800262a4342dcb5a6bab615d08d426e00813d62e022a37e8d0cf36f1c7c03f9b2160bd292d2e01484ef88f20168abf82dc327aa31869d150593191f26c5a5fca589ab22db2", "hex")
    test("Encryption", () => {
        let result = encryptECB(
            key,
            plaintext,
            true,
            sboxes.ID_GOST_28147_89_TEST_PARAM_SET
        )
        
        expect(result).toStrictEqual(encrypted)
    })

    test("Decryption", () => {
        let result = decryptECB(
            key,
            encrypted,
            true,
            sboxes.ID_GOST_28147_89_TEST_PARAM_SET
        )

        expect(result).toStrictEqual(plaintext)
    })
})