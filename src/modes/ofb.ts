import { BLOCK_SIZE, Magma, type Sbox, sboxes } from "../";

import { ofb } from "@li0ard/gost3413"

/**
 * Encrypts data using the Output Feedback (OFB) mode with Magma cipher.
 * 
 * @param key Encryption key
 * @param data Data to be encrypted
 * @param iv Initialization vector
 * @param sbox Optional substitution box, defaults to `ID_TC26_GOST_28147_PARAM_Z`
 * @returns {Uint8Array}
 */
export const encryptOFB = (key: Uint8Array, data: Uint8Array, iv: Uint8Array, sbox: Sbox = sboxes.ID_TC26_GOST_28147_PARAM_Z): Uint8Array => {
    const cipher = new Magma(key, sbox)
    const encrypter = (buf: Uint8Array) => {
        return cipher.encryptBlock(buf)
    }
    return ofb(encrypter, BLOCK_SIZE, data, iv)
}

/**
 * Decrypts data using the Output Feedback (OFB) mode with Magma cipher.
 * 
 * @param key Encryption key
 * @param data Data to be decrypted
 * @param iv Initialization vector
 * @param sbox Optional substitution box, defaults to `ID_TC26_GOST_28147_PARAM_Z`
 * @returns {Uint8Array}
 */
export const decryptOFB = encryptOFB