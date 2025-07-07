import { test, expect } from "bun:test"
import { Magma, sboxes } from "../src"

const key = new Uint8Array([
    0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
    0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
    0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
])

test("Key generation", () => {
    let result = new Magma(key, sboxes.ID_TC26_GOST_28147_PARAM_Z).getRoundKeys()

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
        return new Magma(new Uint8Array(31).fill(1), sboxes.ID_TC26_GOST_28147_PARAM_Z)
    }
    expect(generateInvalid).toThrowError("Invalid key length")
})

test("Zeroed key", () => {
    function generateZeroed() {
        return new Magma(new Uint8Array(32), sboxes.ID_TC26_GOST_28147_PARAM_Z)
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
    const cipher = new Magma(key, sboxes.ID_TC26_GOST_28147_PARAM_Z)

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
    const cipher = new Magma(key, sboxes.ID_TC26_GOST_28147_PARAM_Z)

    for(let i of cases) {
        expect(cipher.transformT(i[0])).toBe(i[1])
    }
})