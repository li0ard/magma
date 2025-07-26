import { concatBytes } from "@li0ard/gost3413/dist/utils";
import { BLOCK_SIZE, decryptECB, encryptCFB, encryptECB, mac_legacy, Magma, type Sbox, sboxes } from "../";
import { kexp15 as kexp15_, kimp15 as kimp15_ } from "@li0ard/gost3413";

/**
 * Key wrapping (GOST 28147-89)
 * @param kek Key encryption key
 * @param cek Content encryption key
 * @param ukm UKM (Initialization vector)
 * @param sbox Optional substitution box, defaults to `ID_GOST_28147_89_CRYPTO_PRO_A_PARAM_SET`
 */
export const wrap = (kek: Uint8Array, cek: Uint8Array, ukm: Uint8Array, sbox: Sbox = sboxes.ID_GOST_28147_89_CRYPTO_PRO_A_PARAM_SET): Uint8Array => {
    let cek_mac = mac_legacy(kek, cek, ukm, sbox).slice(0, 4);
    let cek_enc = encryptECB(kek, cek, true, sbox);
    return concatBytes(ukm, cek_enc, cek_mac);
}

/**
 * Key unwrapping (GOST 28147-89)
 * @param kek Key encryption key
 * @param data Wrapped key
 * @param sbox Optional substitution box, defaults to `ID_GOST_28147_89_CRYPTO_PRO_A_PARAM_SET`
 */
export const unwrap = (kek: Uint8Array, data: Uint8Array, sbox: Sbox = sboxes.ID_GOST_28147_89_CRYPTO_PRO_A_PARAM_SET): Uint8Array => {
    if(data.length !== 44) throw new Error("Invalid data length");

    let [ukm, cek_enc, cek_mac] = [data.slice(0, 8), data.slice(8, 40), data.slice(-4)];
    let cek = decryptECB(kek, cek_enc, true, sbox);
    if(!mac_legacy(kek, cek, ukm, sbox).slice(0, 4).every((value, index) => value === cek_mac[index])) throw new Error("Invalid MAC");

    return cek;
}

/**
 * Key wrapping (CryptoPro)
 * @param kek Key encryption key
 * @param cek Content encryption key
 * @param ukm UKM (Initialization vector)
 * @param sbox Optional substitution box, defaults to `ID_GOST_28147_89_CRYPTO_PRO_A_PARAM_SET`
 */
export const wrapCryptopro = (kek: Uint8Array, cek: Uint8Array, ukm: Uint8Array, sbox: Sbox = sboxes.ID_GOST_28147_89_CRYPTO_PRO_A_PARAM_SET): Uint8Array => {
    return wrap(cp_kek_diversify(kek, ukm, sbox), cek, ukm, sbox);
}

/**
 * Key unwrapping (CryptoPro)
 * @param kek Key encryption key
 * @param data Wrapped key
 * @param sbox Optional substitution box, defaults to `ID_GOST_28147_89_CRYPTO_PRO_A_PARAM_SET`
 */
export const unwrapCryptopro = (kek: Uint8Array, data: Uint8Array, sbox: Sbox = sboxes.ID_GOST_28147_89_CRYPTO_PRO_A_PARAM_SET): Uint8Array => {
    return unwrap(cp_kek_diversify(kek, data.slice(0, 8), sbox), data, sbox);
}

/**
 * CryptoPro KEK Diversification (RFC 4357, section 6.5)
 * @param kek Key encryption key
 * @param ukm UKM (Initialization vector)
 * @param sbox Optional substitution box, defaults to `ID_GOST_28147_89_CRYPTO_PRO_A_PARAM_SET`
 */
export const cp_kek_diversify = (kek: Uint8Array, ukm: Uint8Array, sbox: Sbox = sboxes.ID_GOST_28147_89_CRYPTO_PRO_A_PARAM_SET): Uint8Array => {
    let out: Uint8Array = kek.slice();
    for (let i = 0; i < 8; i++) {
        let s1 = 0, s2 = 0;
        for (let j = 0; j < 8; j++) {
            const k = ((out[j * 4]) | (out[j * 4 + 1] << 8) | (out[j * 4 + 2] << 16) | (out[j * 4 + 3] << 24));
            if ((ukm[i] >> j) & 1) s1 += k;
            else s2 += k;
        }

        const iv = concatBytes(Magma.u32ToBytes(s1 >>> 0).reverse(), Magma.u32ToBytes(s2 >>> 0).reverse())
        out = encryptCFB(out, out, iv, true, sbox);
    }

    return out;
}

/**
 * KExp15 key exporting
 * @param key Key to export
 * @param keyEnc Key for key encryption
 * @param keyMac Key for key authentication
 * @param iv Initialization vector (Half of block size)
 */
export const kexp15 = (key: Uint8Array, keyEnc: Uint8Array, keyMac: Uint8Array, iv: Uint8Array): Uint8Array => {
    const keyCipher = new Magma(keyEnc);
    const keyEncrypter = (block: Uint8Array) => keyCipher.encryptBlock(block);
    const macCipher = new Magma(keyMac);
    const macEncrypter = (block: Uint8Array) => macCipher.encryptBlock(block);
    return kexp15_(keyEncrypter, macEncrypter, BLOCK_SIZE, key, iv);
}

/**
 * KImp15 key importing
 * @param kexp Key to import
 * @param keyEnc Key for key decryption
 * @param keyMac Key for key authentication
 * @param iv Initialization vector (Half of block size)
 */
export const kimp15 = (kexp: Uint8Array, keyEnc: Uint8Array, keyMac: Uint8Array, iv: Uint8Array): Uint8Array => {
    const keyCipher = new Magma(keyEnc);
    const keyEncrypter = (block: Uint8Array) => keyCipher.encryptBlock(block);
    const macCipher = new Magma(keyMac);
    const macEncrypter = (block: Uint8Array) => macCipher.encryptBlock(block);
    return kimp15_(keyEncrypter, macEncrypter, BLOCK_SIZE, kexp, iv);
}