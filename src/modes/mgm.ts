import { BLOCK_SIZE, Magma } from "../index.js";
import { MGM, type TArg, type TRet } from "@li0ard/gost3413";

/**
 * Encrypts data using the Multilinear Galois Mode (MGM) with Magma cipher.
 * @param key Encryption key
 * @param data Data to be encrypted and authenticated
 * @param iv Initialization vector
 * @param additionalData Additional data to be authenticated
 */
export const encryptMGM = (
    key: TArg<Uint8Array>,
    data: TArg<Uint8Array>,
    iv: TArg<Uint8Array>,
    additionalData: TArg<Uint8Array> = new Uint8Array()
): TRet<Uint8Array> => {
    const cipher = new Magma(key);
    const mgm = new MGM(cipher.encryptBlock.bind(cipher), BLOCK_SIZE);

    return mgm.seal(iv.slice(), data.slice(), additionalData.slice());
}

/**
 * Decrypts data using the Multilinear Galois Mode (MGM) with Magma cipher.
 * @param key Encryption key
 * @param data Data to be decrypted and authenticated
 * @param iv Initialization vector
 * @param additionalData Additional data to be authenticated
 */
export const decryptMGM = (
    key: TArg<Uint8Array>,
    data: TArg<Uint8Array>,
    iv: TArg<Uint8Array>,
    additionalData: TArg<Uint8Array> = new Uint8Array()
): TRet<Uint8Array> => {
    const cipher = new Magma(key);
    const mgm = new MGM(cipher.encryptBlock.bind(cipher), BLOCK_SIZE);
    
    return mgm.open(iv.slice(), data.slice(), additionalData.slice());
}