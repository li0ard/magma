import { describe, test, expect } from "bun:test";
import { cp_kek_diversify, unwrap, wrap, kexp15, kimp15, wrapCryptopro, unwrapCryptopro } from "../src/";

describe("Key wrapping", () => {
    const key = Buffer.from("ec44b411637fc66b680e0e721642b99bb1e792ee183cab872254d5850e692ed9", "hex")
    const ukm = Buffer.from("882676dc2ccd53e3", "hex")
    const cek = Buffer.from("76349ba2907d81428f8f1bc06091a2b5bb424d709bb3d1eb47daaf7f47cd3703", "hex")
    const cek_512 = Buffer.from("c98f2ca843ac1a77f66ee183221d476cf27242af5dd69091cb4fe9a4576864a07d8181124e0e5812c14e7ee0b8b9dd7ee0142548192403cd0577021508287d2f", "hex")
    const encrypted = Buffer.from("882676dc2ccd53e36be8cffcf11616cad1ee673b8f364fd7e36a635c4c398d9133832c5694b29defea6196c4", "hex")
    const encrypted_cp = Buffer.from("882676dc2ccd53e328ffbdc874b57f5156ea0700335b22c67dc8a8118e60519f7c39b4385a876cac9a7fd524", "hex")
    const encrypted_512 = Buffer.from("882676dc2ccd53e322a20562bc019feb70b89bb32d9d5149cf1e23c5f7b79241ecad33a787c98dfe3c8b5468526c5ca9d8b2ae2e8f23ec6175b0d3b6b331b2d1aa1ecbde578404facc35efa2", "hex")

    test("Wrap (GOST)", () => {
        expect(wrap(key, cek, ukm)).toStrictEqual(encrypted);
    })

    test("Unwrap (GOST)", () => {
        expect(unwrap(key, encrypted)).toStrictEqual(cek);
    })

    test("Wrap (CryptoPro)", () => {
        expect(wrapCryptopro(key, cek, ukm)).toStrictEqual(encrypted_cp);
    })

    test("Unwrap (CryptoPro)", () => {
        expect(unwrapCryptopro(key, encrypted_cp)).toStrictEqual(cek);
    })

    test("CryptoPro KEK diversify", () =>  {
        const expected = Buffer.from("d8f78085f7eb96766bdedf9450195951450cbbc2c510d588bc1f4ea9f66d39eb", "hex")
        expect(cp_kek_diversify(key, ukm)).toStrictEqual(expected);
    })

    test("Wrap (512 bit)", () => {
        expect(wrap(key, cek_512, ukm)).toStrictEqual(encrypted_512);
    })

    test("Unwrap (512 bit)", () => {
        expect(unwrap(key, encrypted_512)).toStrictEqual(cek_512);
    })
})

describe("Key wrapping", () => {
    const key = Buffer.from("8899AABBCCDDEEFF0011223344556677FEDCBA98765432100123456789ABCDEF", "hex");
    const keyEnc = Buffer.from("202122232425262728292A2B2C2D2E2F38393A3B3C3D3E3F3031323334353637", "hex");
    const keyMac = Buffer.from("08090A0B0C0D0E0F0001020304050607101112131415161718191A1B1C1D1E1F", "hex");
    const iv = Buffer.from("67BED654", "hex");
    const kexp = Buffer.from("CFD5A12D5B81B6E1E99C916D07900C6AC12703FB3ABDED55567BF3742C899C755DAFE7B42E3A8BD9", "hex");
    test("KExp15", () => {
        expect(kexp15(key, keyEnc, keyMac, iv)).toStrictEqual(kexp);
    })
    test("KImp15", () => {
        expect(kimp15(kexp, keyEnc, keyMac, iv)).toStrictEqual(key);
    })
})