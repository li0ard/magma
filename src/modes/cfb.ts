import { BLOCK_SIZE, Magma, type Sbox, sboxes } from "../";
import { cfb_encrypt, cfb_decrypt } from "@li0ard/gost3413";

/**
 * Encrypts data using Cipher Feedback (CFB) mode with Magma cipher
 * 
 * @param key Encryption key
 * @param data Data to be encrypted
 * @param iv Initialization vector
 * @param legacy Enable backward compatibility with old GOST 28147-89
 * @param sbox Optional substitution box, defaults to `ID_TC26_GOST_28147_PARAM_Z`
 * @returns {Uint8Array}
 */
export const encryptCFB = (key: Uint8Array, data: Uint8Array, iv: Uint8Array, legacy: boolean = false, sbox: Sbox = sboxes.ID_TC26_GOST_28147_PARAM_Z): Uint8Array => {
    const cipher = new Magma(legacy ? Magma.reverseKey(key) : key, sbox);
    const encrypter = (buf: Uint8Array) => (legacy ? cipher.encryptLegacy(buf) : cipher.encryptBlock(buf));
    return cfb_encrypt(encrypter, BLOCK_SIZE, data, iv);
}

/**
 * Decrypts data using Cipher Feedback (CFB) mode with Magma cipher
 * 
 * @param key Encryption key
 * @param data Data to be decrypted
 * @param iv Initialization vector
 * @param legacy Enable backward compatibility with old GOST 28147-89
 * @param sbox Optional substitution box, defaults to `ID_TC26_GOST_28147_PARAM_Z`
 * @returns {Uint8Array}
 */
export const decryptCFB = (key: Uint8Array, data: Uint8Array, iv: Uint8Array, legacy: boolean = false, sbox: Sbox = sboxes.ID_TC26_GOST_28147_PARAM_Z): Uint8Array => {
    const cipher = new Magma(legacy ? Magma.reverseKey(key) : key, sbox)
    const decrypter = (buf: Uint8Array) => (legacy ? cipher.encryptLegacy(buf) : cipher.encryptBlock(buf));
    return cfb_decrypt(decrypter, BLOCK_SIZE, data, iv);
}