import { BLOCK_SIZE, Magma, type Sbox, sboxes } from "../index.js";
import { ofb, type TArg, type TRet } from "@li0ard/gost3413";

/**
 * Encrypts data using the Output Feedback (OFB) mode with Magma cipher.
 * 
 * @param key Encryption key
 * @param data Data to be encrypted
 * @param iv Initialization vector
 * @param sbox Optional substitution box, defaults to `ID_TC26_GOST_28147_PARAM_Z`
 */
export const encryptOFB = (
    key: TArg<Uint8Array>,
    data: TArg<Uint8Array>,
    iv: TArg<Uint8Array>,
    sbox: Sbox = sboxes.ID_TC26_GOST_28147_PARAM_Z
): TRet<Uint8Array> => {
    const cipher = new Magma(key, sbox);
    return ofb(cipher.encryptBlock.bind(cipher), BLOCK_SIZE, data, iv);
}

/**
 * Decrypts data using the Output Feedback (OFB) mode with Magma cipher.
 * 
 * @param key Encryption key
 * @param data Data to be decrypted
 * @param iv Initialization vector
 * @param sbox Optional substitution box, defaults to `ID_TC26_GOST_28147_PARAM_Z`
 */
export const decryptOFB = encryptOFB;