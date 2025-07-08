import { Magma, type Sbox, sboxes, BLOCK_SIZE } from "../";
import { ecb_encrypt, ecb_decrypt } from "@li0ard/gost3413"

/**
 * Encrypts data using Electronic Codebook (ECB) mode with Magma cipher.
 * 
 * @param key Encryption key
 * @param data Data to be encrypted
 * @param sbox Optional substitution box, defaults to `ID_TC26_GOST_28147_PARAM_Z`
 * @returns {Uint8Array}
 */
export const encryptECB = (key: Uint8Array, data: Uint8Array, sbox: Sbox = sboxes.ID_TC26_GOST_28147_PARAM_Z): Uint8Array => {
    const cipher = new Magma(key, sbox)
    const encrypter = (buf: Uint8Array) => {
        return cipher.encryptBlock(buf)
    }
    return ecb_encrypt(encrypter, BLOCK_SIZE, data)
}

/**
 * Decrypts data using Electronic Codebook (ECB) mode with Magma cipher.
 * 
 * @param key Encryption key
 * @param data Data to be decrypted
 * @param sbox Optional substitution box, defaults to `ID_TC26_GOST_28147_PARAM_Z`
 * @returns {Uint8Array}
 */
export const decryptECB = (key: Uint8Array, data: Uint8Array, sbox: Sbox = sboxes.ID_TC26_GOST_28147_PARAM_Z): Uint8Array => {
    const cipher = new Magma(key, sbox)
    const decrypter = (buf: Uint8Array) => {
        return cipher.decryptBlock(buf)
    }
    return ecb_decrypt(decrypter, BLOCK_SIZE, data)
}