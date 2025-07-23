import { BLOCK_SIZE, Magma } from "../";
import { kexp15 as kexp15_, kimp15 as kimp15_ } from "@li0ard/gost3413";

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