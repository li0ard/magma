import { BLOCK_SIZE, CipherError, KEY_SIZE, keySequences, sboxes, type Sbox } from "./const";
import { concatBytes } from "@li0ard/gost3413/dist/utils";

/** Magma core class */
export class Magma {
    private roundKeys: number[] = [];

    /**
     * Magma core class
     * @param key Encryption key
     * @param sbox S-Box
     */
    constructor(private key: Uint8Array, private sbox: Sbox = sboxes.ID_TC26_GOST_28147_PARAM_Z) {
        if (key.length !== KEY_SIZE) throw new CipherError("Invalid key length");
        if (key.every(byte => byte === 0)) throw new CipherError("Invalid key format");

        this.roundKeys = this.regenerateRoundKeys(keySequences.ENCRYPT)
    }

    /** Regenerate round keys for sequence */
    public regenerateRoundKeys(sequence: number[]): number[] {
        const keyChunks: number[] = [];
        for (let j = 0; j < 8; j++) keyChunks.push(Magma.bytesToU32(this.key.slice(j * 4, j * 4 + 4)));
        let roundKeys = new Array(sequence.length);
        for (let i = 0; i < sequence.length; i++) roundKeys[i] = keyChunks[sequence[i]];

        return roundKeys
    }

    /**
     * Applies substitution transformation (T-transformation) using S-box.
     * Breaks input value into 4-bit parts, substitutes each part using corresponding S-box row,
     * and reconstructs transformed value.
     * @param value Value to be transformed
     * @returns {number} Transformed 32-bit value after substitution
    */
    public transformT(value: number): number {
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
    public transformG(a: number, k: number): number {
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
     * @throws {CipherError} Block size is invalid or data is too short
     */
    public proceedBlock(block: Uint8Array, sequence: number[]): Uint8Array {
        let roundKeys = this.regenerateRoundKeys(sequence);
        if (block.length !== BLOCK_SIZE) throw new CipherError("Invalid block size");

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
    public encryptBlock(block: Uint8Array): Uint8Array {
        return this.proceedBlock(block, keySequences.ENCRYPT)
    }

    /**
     * Decrypts single block of data using Magma cipher.
     * @param block Block to be decrypted
     */
    public decryptBlock(block: Uint8Array): Uint8Array {
        return this.proceedBlock(block, keySequences.DECRYPT)
    }

    /** Encrypt single block of data using old Magma (GOST 28147-89) algorithm */
    public encryptLegacy(block: Uint8Array): Uint8Array {
        return Magma.reverseChunks(this.encryptBlock(Magma.reverseChunks(block)));
    }

    /** Decrypt single block of data using old Magma (GOST 28147-89) algorithm */
    public decryptLegacy(block: Uint8Array): Uint8Array {
        return Magma.reverseChunks(this.decryptBlock(Magma.reverseChunks(block)));
    }

    /** Convert bytes to uint32 number */
    public static bytesToU32(bytes: Uint8Array): number {
        return ((bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3]) >>> 0;
    }

    /** Convert uint32 number to bytes */
    public static u32ToBytes(value: number): Uint8Array {
        return new Uint8Array([(value >> 24) & 0xff, (value >> 16) & 0xff, (value >> 8) & 0xff, value & 0xff]);
    }

    /** Backward compatibility key preparation for 28147-89 key schedule */
    public static reverseKey(key: Uint8Array): Uint8Array {
        const result = new Uint8Array(KEY_SIZE);
        for (let i = 0; i < BLOCK_SIZE; i++) result.set(new Uint8Array(key.slice(i * 4, i * 4 + 4)).reverse(), i * 4);
        return result;
    }

    /** Backward compatibility block preparation for 28147-89 */
    public static reverseChunks(data: Uint8Array): Uint8Array {
        const chunks: Uint8Array[] = [];
        for (let i = 0; i < data.length; i += BLOCK_SIZE) chunks.push(new Uint8Array(data.slice(i, i + BLOCK_SIZE)).reverse());

        return concatBytes(...chunks);
    }
}

export * from "./const";
export * from "./modes/ecb";
export * from "./modes/cbc";
export * from "./modes/cfb";
export * from "./modes/ctr";
export * from "./modes/ofb";
export * from "./modes/mac";
export * from "./modes/acpkm";
export * from "./modes/mgm";
export * from "./modes/wrap";