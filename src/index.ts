import { BLOCK_SIZE, KEY_SIZE, keySequences, sboxes, type Sbox } from "./const.js";
import { concatBytes, type TArg, type TRet } from "@li0ard/gost3413";

/** Magma core class */
export class Magma {
    private roundKeys: number[] = [];

    /**
     * Magma core class
     * @param key Encryption key
     * @param sbox S-Box
     */
    constructor(private key: TArg<Uint8Array>, private sbox: Sbox = sboxes.ID_TC26_GOST_28147_PARAM_Z) {
        if (key.length !== KEY_SIZE) throw new Error("Invalid key length");
        this.roundKeys = this.regenerateRoundKeys(keySequences.ENCRYPT);
    }

    /** Regenerate round keys for sequence */
    public regenerateRoundKeys(sequence: number[]): number[] {
        const keyChunks: number[] = [];
        for (let j = 0; j < 8; j++) keyChunks.push(Magma.bytesToU32(this.key.slice(j * 4, j * 4 + 4)));
        let roundKeys = new Array(sequence.length);
        for (let i = 0; i < sequence.length; i++) roundKeys[i] = keyChunks[sequence[i]];

        return roundKeys;
    }

    /**
     * Applies substitution transformation (T-transformation) using S-box.
     * Breaks input value into 4-bit parts, substitutes each part using corresponding S-box row,
     * and reconstructs transformed value.
     * @param value Value to be transformed
     * @returns {number} Transformed 32-bit value after substitution
    */
    private transformT(value: number): number {
        let result = 0;
        for (let i = 0; i < 8; i++) result |= this.sbox[i][(value >> (4 * i)) & 0x0f] << (4 * i);
        return result >>> 0;
    }

    /**
     * Applies the G-transformation (Feistel round function) to input value.
     * Performs addition with round key, applies T-transformation, and performs cyclic left shift.
     * @param a Input 32-bit value to be transformed
     * @param k Round key used in the transformation
     * @returns {number} Transformed 32-bit value after G-transformation
     */
    private transformG(a: number, k: number): number {
        const substituted = this.transformT((a + k) >>> 0);
        return ((substituted << 11) | (substituted >>> 21)) >>> 0;
    }

    /**
     * Returns round keys
     * @returns {number[]}
     */
    public getRoundKeys(): number[] {
        return [...this.roundKeys]; 
    }

    /**
     * Proceed single block of data using Magma cipher
     * @param block Block
     * @param sequence Sequence of `K_i` S-Box applying
     * @returns {Uint8Array} Proceeded block
     */
    public proceedBlock(block: TArg<Uint8Array>, sequence: number[]): TRet<Uint8Array> {
        let roundKeys = this.regenerateRoundKeys(sequence);
        if (block.length !== BLOCK_SIZE) throw new Error("Invalid block size");

        let a0 = Magma.bytesToU32(block.slice(0, 4));
        let a1 = Magma.bytesToU32(block.slice(4, 8));

        for (let i = 0; i < roundKeys.length; i++) {
            const temp = a1;
            a1 = a0 ^ this.transformG(a1, roundKeys[i]);
            a0 = temp;
        }

        return concatBytes(Magma.u32ToBytes(a1), Magma.u32ToBytes(a0));
    }

    /**
     * Encrypts single block of data using Magma cipher.
     * @param block Block to be encrypted
     */
    public encryptBlock(block: TArg<Uint8Array>): TRet<Uint8Array> {
        return this.proceedBlock(block, keySequences.ENCRYPT);
    }

    /**
     * Decrypts single block of data using Magma cipher.
     * @param block Block to be decrypted
     */
    public decryptBlock(block: TArg<Uint8Array>): TRet<Uint8Array> {
        return this.proceedBlock(block, keySequences.DECRYPT);
    }

    /** Encrypt single block of data using old Magma (GOST 28147-89) algorithm */
    public encryptLegacy(block: TArg<Uint8Array>): TRet<Uint8Array> {
        return Magma.reverseChunks(this.encryptBlock(Magma.reverseChunks(block)));
    }

    /** Decrypt single block of data using old Magma (GOST 28147-89) algorithm */
    public decryptLegacy(block: TArg<Uint8Array>): TRet<Uint8Array> {
        return Magma.reverseChunks(this.decryptBlock(Magma.reverseChunks(block)));
    }

    /** Convert bytes to uint32 number */
    public static bytesToU32(bytes: TArg<Uint8Array>): number {
        return ((bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3]) >>> 0;
    }

    /** Convert uint32 number to bytes */
    public static u32ToBytes(value: number): TRet<Uint8Array> {
        return new Uint8Array([(value >> 24) & 0xff, (value >> 16) & 0xff, (value >> 8) & 0xff, value & 0xff]);
    }

    /** Backward compatibility key preparation for 28147-89 key schedule */
    public static reverseKey(key: TArg<Uint8Array>): TRet<Uint8Array> {
        const result = new Uint8Array(KEY_SIZE);
        for (let i = 0; i < BLOCK_SIZE; i++)
            result.set(new Uint8Array(key.slice(i * 4, i * 4 + 4)).reverse(), i * 4);
        return result;
    }

    /** Backward compatibility block preparation for 28147-89 */
    public static reverseChunks(data: TArg<Uint8Array>): TRet<Uint8Array> {
        const chunks: Uint8Array[] = [];
        for (let i = 0; i < data.length; i += BLOCK_SIZE)
            chunks.push(new Uint8Array(data.slice(i, i + BLOCK_SIZE)).reverse());

        return concatBytes(...chunks);
    }
}

export * from "./const.js";
export * from "./modes/ecb.js";
export * from "./modes/cbc.js";
export * from "./modes/cfb.js";
export * from "./modes/ctr.js";
export * from "./modes/ofb.js";
export * from "./modes/mac.js";
export * from "./modes/acpkm.js";
export * from "./modes/mgm.js";
export * from "./modes/wrap.js";