import { test, expect } from "bun:test"
import { Magma } from "../src"

const key = Buffer.from("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", "hex")

test("Key generation", () => {
    let result = new Magma(key).getRoundKeys()

    let expected = [
        0xffeeddcc, 0xbbaa9988, 0x77665544, 0x33221100,
        0xf0f1f2f3, 0xf4f5f6f7, 0xf8f9fafb, 0xfcfdfeff,
        0xffeeddcc, 0xbbaa9988, 0x77665544, 0x33221100,
        0xf0f1f2f3, 0xf4f5f6f7, 0xf8f9fafb, 0xfcfdfeff,
        0xffeeddcc, 0xbbaa9988, 0x77665544, 0x33221100,
        0xf0f1f2f3, 0xf4f5f6f7, 0xf8f9fafb, 0xfcfdfeff,
        0xfcfdfeff, 0xf8f9fafb, 0xf4f5f6f7, 0xf0f1f2f3,
        0x33221100, 0x77665544, 0xbbaa9988, 0xffeeddcc,
    ];

    expect(result).toStrictEqual(expected)
})

test("Invalid key", () => {
    function generateInvalid() {
        return new Magma(new Uint8Array(31).fill(1))
    }
    expect(generateInvalid).toThrowError("Invalid key length")
})

test("Zeroed key", () => {
    function generateZeroed() {
        return new Magma(new Uint8Array(32))
    }
    expect(generateZeroed).toThrowError("Invalid key format")
})

test("Transform G", () => {
    let cases = [
        [0x87654321, 0xfedcba98, 0xfdcbc20c],
        [0xfdcbc20c, 0x87654321, 0x7e791a4b],
        [0x7e791a4b, 0xfdcbc20c, 0xc76549ec],
        [0xc76549ec, 0x7e791a4b, 0x9791c849],
    ]
    const cipher = new Magma(key)

    for(let i of cases) {
        expect(cipher.transformG(i[0], i[1])).toBe(i[2])
    }
})

test("Transform T", () => {
    let cases = [
        [0xfdb97531, 0x2a196f34],
        [0x2a196f34, 0xebd9f03a],
        [0xebd9f03a, 0xb039bb3d],
        [0xb039bb3d, 0x68695433]
    ]
    const cipher = new Magma(key)

    for(let i of cases) {
        expect(cipher.transformT(i[0])).toBe(i[1])
    }
})