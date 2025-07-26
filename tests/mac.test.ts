import { describe, test, expect } from "bun:test";
import { mac, mac_legacy } from "../src";

const key = Buffer.from("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", "hex");
const plaintext = Buffer.from("92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41", "hex");
const computed = Buffer.from("154e72102030c5bb", "hex");

test("MAC", () => {
    expect(mac(key, plaintext)).toStrictEqual(computed);
})

describe("MAC (GOST 28147-89)", () => {
    let k = Buffer.from("54686973206973206d657373616765ff206c656e677468003332206279746573", "hex")
    test("#1", () => {
        let expected = Buffer.from("b6ff8873ca1a407f", "hex")
        expect(mac_legacy(k, Buffer.from("616263", "hex"), Buffer.from("6161616161616161", "hex"))).toStrictEqual(expected)
    })
    test("#2", () => {
        let expected = Buffer.from("28661e40805b1ff9", "hex")
        expect(mac_legacy(k, Buffer.from("616263", "hex"))).toStrictEqual(expected)
    })
    test("#3", () => {
        let expected = Buffer.from("bd5d3b5b2b7b57af", "hex")
        expect(mac_legacy(k, Buffer.from("61", "hex"))).toStrictEqual(expected)
    })
    test("#4", () => {
        let expected = Buffer.from("917ee1f1a668fbd3", "hex")
        expect(mac_legacy(k, new Uint8Array(13).fill(0x78))).toStrictEqual(expected)
    })
    test("#5", () => {
        let expected = Buffer.from("1a06d1bad74580ef", "hex")
        expect(mac_legacy(k, new Uint8Array(128).fill(0x55))).toStrictEqual(expected)
    })
})