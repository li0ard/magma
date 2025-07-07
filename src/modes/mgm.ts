import { BLOCK_SIZE, Magma, sboxes } from "../"
import { MGM } from "@li0ard/gost3413"

/**
 * Encrypts data using the Multilinear Galois Mode (MGM) with Magma cipher.
 * @param key Encryption key
 * @param data Data to be encrypted and authenticated
 * @param iv Initialization vector
 * @param additionalData Additional data to be authenticated
 */
export const encryptMGM = (key: Uint8Array, data: Uint8Array, iv: Uint8Array, additionalData: Uint8Array = new Uint8Array()): Uint8Array => {
    const cipher = new Magma(key)
    const encrypter = (buf: Uint8Array) => {
        return cipher.encryptBlock(buf)
    }

    let mgm = new MGM(encrypter, BLOCK_SIZE)
    return mgm.seal(iv.slice(), data.slice(), additionalData.slice())
}

/**
 * Decrypts data using the Multilinear Galois Mode (MGM) with Magma cipher.
 * @param key Encryption key
 * @param data Data to be decrypted and authenticated
 * @param iv Initialization vector
 * @param additionalData Additional data to be authenticated
 */
export const decryptMGM = (key: Uint8Array, data: Uint8Array, iv: Uint8Array, additionalData: Uint8Array = new Uint8Array()): Uint8Array => {
    const cipher = new Magma(key)
    const encrypter = (buf: Uint8Array) => {
        return cipher.encryptBlock(buf)
    }

    let mgm = new MGM(encrypter, BLOCK_SIZE)
    return mgm.open(iv.slice(), data.slice(), additionalData.slice())
}