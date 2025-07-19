import { BLOCK_SIZE, CipherError, KEY_SIZE, ROUNDS, sboxes, type Sbox } from "./const";
import { concatBytes } from "@li0ard/gost3413/dist/utils"

/** Magma core class */
export class Magma {
    private roundKeys: number[] = new Array(ROUNDS).fill(0);
    private sbox: Sbox;

    /**
     * Magma core class
     * @param key Encryption key
     * @param sbox S-Box
     */
    constructor(key: Uint8Array, sbox: Sbox = sboxes.ID_TC26_GOST_28147_PARAM_Z) {
        if (key.length !== KEY_SIZE) throw new CipherError("Invalid key length");
        if (key.every(byte => byte === 0)) throw new CipherError("Invalid key format");
        this.sbox = sbox;

        // Generation of round keys
        // First 24 round keys
        for (let i = 0; i < 3; i++) {
            for (let j = 0; j < 8; j++) {
                const offset = j * 4;
                const keyChunk = key.slice(offset, offset + 4);
                this.roundKeys[j + i * 8] = Magma.bytesToU32(keyChunk);
            }
        }

        // Last 8 round keys
        const keyChunks = [];
        for (let j = 0; j < 8; j++) {
            const offset = j * 4;
            keyChunks.push(key.slice(offset, offset + 4));
        }

        for (let j = 0; j < 8; j++) {
            const keyChunk = keyChunks[7 - j];
            this.roundKeys[j + 24] = Magma.bytesToU32(keyChunk);
        }
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
        for (let i = 0; i < 8; i++) {
            result |= this.sbox[i][(value >> (4 * i)) & 0x0f] << (4 * i);
        }
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
        const temp = (a + k) >>> 0;
        const substituted = this.transformT(temp);
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
     * Encrypts single block of data using Magma (Feistel network) encryption algorithm.
     * @param block Block to be encrypted
     * @returns {Uint8Array} Encrypted block
     * @throws {CipherError} Block size is invalid or data is too short
     */
    public encryptBlock(block: Uint8Array): Uint8Array {
        if (block.length === 0 || block.length !== BLOCK_SIZE) throw new CipherError("Invalid block size");

        let a0 = Magma.bytesToU32(block.slice(0, 4));
        let a1 = Magma.bytesToU32(block.slice(4, 8));

        for (let i = 0; i < ROUNDS; i++) {
            const temp = a1;
            a1 = a0 ^ this.transformG(a1, this.roundKeys[i]);
            a0 = temp;
        }

        const result = new Uint8Array(BLOCK_SIZE);
        Magma.writeU32ToBytes(a1, result, 0);
        Magma.writeU32ToBytes(a0, result, 4);
        return result;
    }

    /**
     * Decrypts single block of data using Magma (Feistel network) encryption algorithm.
     * @param block Block to be decrypted
     * @returns {Uint8Array} Decrypted block
     * @throws {CipherError} Block size is invalid or data is too short
     */
    public decryptBlock(block: Uint8Array): Uint8Array {
        if (block.length === 0 || block.length !== BLOCK_SIZE) throw new CipherError("Invalid block size");

        let a0 = Magma.bytesToU32(block.slice(0, 4));
        let a1 = Magma.bytesToU32(block.slice(4, 8));

        for (let i = ROUNDS - 1; i >= 0; i--) {
            const temp = a1;
            a1 = a0 ^ this.transformG(a1, this.roundKeys[i]);
            a0 = temp;
        }

        const result = new Uint8Array(BLOCK_SIZE);
        Magma.writeU32ToBytes(a1, result, 0);
        Magma.writeU32ToBytes(a0, result, 4);
        return result;
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
    public static writeU32ToBytes(value: number, buffer: Uint8Array, offset: number): void {
        buffer[offset] = (value >> 24) & 0xff;
        buffer[offset + 1] = (value >> 16) & 0xff;
        buffer[offset + 2] = (value >> 8) & 0xff;
        buffer[offset + 3] = value & 0xff;
    }

    /** Backward compatibility key preparation for 28147-89 key schedule */
    public static reverseKey(key: Uint8Array): Uint8Array {
        const result = new Uint8Array(32);
        for (let i = 0; i < 8; i++) {
            const start = i * 4;
            let chunk = new Uint8Array(key.slice(start, start + 4))
            result.set(chunk.reverse(), start);
        }
        return result
    }

    /** Backward compatibility block preparation for 28147-89 */
    public static reverseChunks(data: Uint8Array): Uint8Array {
        const chunks: Uint8Array[] = [];
        for (let i = 0; i < data.length; i += BLOCK_SIZE) {
            let chunk = new Uint8Array(data.slice(i, i + BLOCK_SIZE))
            chunks.push(chunk.reverse());
        }

        return concatBytes(...chunks);
    }
}

export * from "./const"
export * from "./modes/ecb"
export * from "./modes/cbc"
export * from "./modes/cfb"
export * from "./modes/ctr"
export * from "./modes/ofb"
export * from "./modes/mac"
export * from "./modes/acpkm"
export * from "./modes/mgm"