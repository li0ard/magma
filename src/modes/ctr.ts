import { BLOCK_SIZE, Magma, type Sbox, sboxes } from "../index.js";
import { ctr, getPadLength, type TArg, concatBytes, xor, type CipherFunc, type TRet } from "@li0ard/gost3413";

/** Magma `CNT` (not `CTR`, but similar) mode */
const cnt = (encrypter: CipherFunc, data: TArg<Uint8Array>, iv: TArg<Uint8Array>): TRet<Uint8Array> => {
    if(iv.length !== BLOCK_SIZE) throw new Error("Invalid IV size");
    const C1 = 0x01010104;
    const C2 = 0x01010101;

    const encryptedIv = encrypter(iv).reverse();
    
    let n2 = Magma.bytesToU32(encryptedIv.slice(0, 4));
    let n1 = Magma.bytesToU32(encryptedIv.slice(4));

    const gamma: Uint8Array[] = [];

    for (let i = 0; i < (data.length + getPadLength(data.length, BLOCK_SIZE)); i += BLOCK_SIZE) {
        n1 = (n1 + C2) % 0x100000000;
        n2 = (n2 + C1) % 0xFFFFFFFF;
        gamma.push(encrypter(concatBytes(Magma.u32ToBytes(n2), Magma.u32ToBytes(n1)).reverse()));
    }

    return xor(concatBytes(...gamma), data);
}

/**
 * Encrypts data using the Counter (CTR) mode with Magma cipher.
 * 
 * @param key Encryption key
 * @param data Data to be encrypted
 * @param iv Initialization vector
 * @param legacy Enable backward compatibility with old GOST 28147-89
 * @param sbox Optional substitution box, defaults to `ID_TC26_GOST_28147_PARAM_Z`
 */
export const encryptCTR = (
    key: TArg<Uint8Array>,
    data: TArg<Uint8Array>,
    iv: TArg<Uint8Array>,
    legacy: boolean = false,
    sbox: Sbox = sboxes.ID_TC26_GOST_28147_PARAM_Z
): TRet<Uint8Array> => {
    const cipher = new Magma(legacy ? Magma.reverseKey(key) : key, sbox);
    const encrypter = (buf: TArg<Uint8Array>) => (legacy ? cipher.encryptLegacy(buf) : cipher.encryptBlock(buf));
    if(legacy) return cnt(encrypter, data, iv);
    return ctr(encrypter, BLOCK_SIZE, data, iv);
}

/**
 * Decrypts data using the Counter (CTR) mode with Magma cipher.
 * 
 * @param key Encryption key
 * @param data Data to be decrypted
 * @param iv Initialization vector
 * @param legacy Enable backward compatibility with old GOST 28147-89
 * @param sbox Optional substitution box, defaults to `ID_TC26_GOST_28147_PARAM_Z`
 */
export const decryptCTR = encryptCTR;