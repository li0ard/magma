import { BLOCK_SIZE, Magma, type Sbox, sboxes } from "../index.js";
import { cbc_encrypt, cbc_decrypt, type TArg, type TRet } from "@li0ard/gost3413";

/**
 * Encrypts data using Cipher Block Chaining (CBC) mode with the Magma cipher.
 * 
 * @param key Encryption key
 * @param data Data to be encrypted
 * @param iv Initialization vector
 * @param legacy Enable backward compatibility with old GOST 28147-89
 * @param sbox Optional substitution box, defaults to `ID_TC26_GOST_28147_PARAM_Z`
 */
export const encryptCBC = (
    key: TArg<Uint8Array>,
    data: TArg<Uint8Array>,
    iv: TArg<Uint8Array>,
    legacy: boolean = false, 
    sbox: Sbox = sboxes.ID_TC26_GOST_28147_PARAM_Z
): TRet<Uint8Array> => {
    const cipher = new Magma(legacy ? Magma.reverseKey(key) : key, sbox);
    return cbc_encrypt((legacy ? cipher.encryptLegacy : cipher.encryptBlock).bind(cipher), BLOCK_SIZE, data, iv);
}

/**
 * Decrypts data using Cipher Block Chaining (CBC) mode with the Magma cipher.
 * 
 * @param key Encryption key
 * @param data Data to be decrypted
 * @param iv Initialization vector
 * @param legacy Enable backward compatibility with old GOST 28147-89
 * @param sbox Optional substitution box, defaults to `ID_TC26_GOST_28147_PARAM_Z`
 */
export const decryptCBC = (
    key: TArg<Uint8Array>,
    data: TArg<Uint8Array>,
    iv: TArg<Uint8Array>,
    legacy: boolean = false,
    sbox: Sbox = sboxes.ID_TC26_GOST_28147_PARAM_Z
): TRet<Uint8Array> => {
    const cipher = new Magma(legacy ? Magma.reverseKey(key) : key, sbox);
    return cbc_decrypt((legacy ? cipher.decryptLegacy : cipher.decryptBlock).bind(cipher), BLOCK_SIZE, data, iv);
}