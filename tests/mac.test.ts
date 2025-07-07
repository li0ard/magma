import { test, expect } from "bun:test"
import { mac } from "../src"

const key = Buffer.from("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", "hex")
const plaintext = Buffer.from("92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17b57e41", "hex")
const computed = Buffer.from("154e72102030c5bb", "hex")

test("MAC", () => {
    let result = mac(key, plaintext)
    expect(result).toStrictEqual(computed)
})