import { xor } from "@li0ard/gost3413/dist/utils";
import { BLOCK_SIZE, keySequences, Magma, type Sbox, sboxes } from "../";
import { mac as mac_, pad1 } from "@li0ard/gost3413";

/**
 * Compute MAC with Magma cipher (GOST 28147-89)
 * @param key Encryption key
 * @param data Input data
 * @param iv Initialization vector
 * @param sbox Optional substitution box, defaults to `ID_GOST_28147_89_CRYPTO_PRO_A_PARAM_SET`
 */
export const mac_legacy = (key: Uint8Array, data: Uint8Array, iv: Uint8Array = new Uint8Array(BLOCK_SIZE), sbox: Sbox = sboxes.ID_GOST_28147_89_CRYPTO_PRO_A_PARAM_SET): Uint8Array => {
    const split = (data: Uint8Array): number[] => {
        return [
            (data[0] | data[1] << 8 | data[2] << 16 | data[3] << 24) >>> 0,
            (data[4] | data[5] << 8 | data[6] << 16 | data[7] << 24) >>> 0
        ];
    }
    const join = (ns: number[]): Uint8Array => {
        return new Uint8Array([
            (ns[1] >> 0) & 0xFF, (ns[1] >> 8) & 0xFF, (ns[1] >> 16) & 0xFF, (ns[1] >> 24) & 0xFF,
            (ns[0] >> 0) & 0xFF, (ns[0] >> 8) & 0xFF, (ns[0] >> 16) & 0xFF, (ns[0] >> 24) & 0xFF
        ]);
    }
    let cipher = new Magma(Magma.reverseKey(key), sbox)
    cipher.regenerateRoundKeys(keySequences.MAC);
    let paddedData = pad1(data, BLOCK_SIZE);

    let prev = split(iv).reverse();
    for(let i = 0; i < paddedData.length; i += BLOCK_SIZE) {
        prev = split(Magma.reverseChunks(cipher.proceedBlock(
            Magma.reverseChunks(xor(paddedData.slice(i, i + BLOCK_SIZE), join(prev))),
            keySequences.MAC
        )));
    }

    return join(prev);
}

/**
 * Compute MAC with Magma cipher
 * @param key Encryption key
 * @param data Input data
 * @param sbox Optional substitution box, defaults to `ID_TC26_GOST_28147_PARAM_Z`
 */
export const mac = (key: Uint8Array, data: Uint8Array, sbox: Sbox = sboxes.ID_TC26_GOST_28147_PARAM_Z): Uint8Array => {
    const cipher = new Magma(key, sbox);
    const encrypter = (buf: Uint8Array) => cipher.encryptBlock(buf);
    return mac_(encrypter, BLOCK_SIZE, data);
}