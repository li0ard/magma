import { BLOCK_SIZE, Magma, type Sbox, sboxes } from "../"
import { mac as mac_ } from "@li0ard/gost3413"

/**
 * Compute MAC (CMAC, OMAC1) with Magma cipher
 * @param key Encryption key
 * @param data Input data
 * @param sbox Optional substitution box, defaults to `ID_TC26_GOST_28147_PARAM_Z`
 */
export const mac = (key: Uint8Array, data: Uint8Array, sbox: Sbox = sboxes.ID_TC26_GOST_28147_PARAM_Z): Uint8Array => {
    const cipher = new Magma(key, sbox)
    const encrypter = (buf: Uint8Array) => {
        return cipher.encryptBlock(buf)
    }
    return mac_(encrypter, BLOCK_SIZE, data)
}