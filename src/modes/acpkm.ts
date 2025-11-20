import { BLOCK_SIZE, Magma } from "../index.js";
import { ctr_acpkm, acpkmDerivation as acpkmDerivation_, acpkmDerivationMaster as acpkmDerivationMaster_, KEYSIZE, omac_acpkm_master } from "@li0ard/gost3413";

/**
 * Encrypts data using the Counter with Advance Cryptographic Prolongation of Key Material (CTR-ACPKM) mode with Magma cipher.
 * 
 * @param key Encryption key
 * @param data Data to be encrypted
 * @param iv Initialization vector
 * @returns {Uint8Array}
 */
export const encryptCTR_ACPKM = (key: Uint8Array, data: Uint8Array, iv: Uint8Array): Uint8Array => {
    class ACPKMClass extends Magma {
        encrypt(block: Uint8Array): Uint8Array { return this.encryptBlock(block); }
    }
    
    const cipher = new Magma(key);
    return ctr_acpkm(ACPKMClass, cipher.encryptBlock.bind(cipher), BLOCK_SIZE * 2, BLOCK_SIZE, data, iv);
}

/**
 * Decrypts data using Counter with Advance Cryptographic Prolongation of Key Material (CTR-ACPKM) mode with Magma cipher.
 * 
 * @param key Encryption key
 * @param data Data to be decrypted
 * @param iv Initialization vector
 * @returns {Uint8Array}
 */
export const decryptCTR_ACPKM = encryptCTR_ACPKM

/**
 * ACPKM key derivation
 * @param key Encryption key
 */
export const acpkmDerivation = (key: Uint8Array): Uint8Array => {
    const cipher = new Magma(key);
    return acpkmDerivation_(cipher.encryptBlock.bind(cipher), BLOCK_SIZE);
}

/**
 * ACPKM master key derivation
 * @param key Encryption key
 * @param keySize Length of key material
 */
export const acpkmDerivationMaster = (key: Uint8Array, keySize: number): Uint8Array => {
    class ACPKMClass extends Magma {
        encrypt(block: Uint8Array): Uint8Array { return this.encryptBlock(block); }
    }

    const cipher = new Magma(key);
    return acpkmDerivationMaster_(ACPKMClass, cipher.encryptBlock.bind(cipher), 80, BLOCK_SIZE, keySize * (KEYSIZE + BLOCK_SIZE));
}

/**
 * Compute MAC with Advance Cryptographic Prolongation of Key Material (OMAC-ACPKM) with Magma cipher
 * @param key Encryption key
 * @param data Input data
 */
export const omac_ACPKM = (key: Uint8Array, data: Uint8Array): Uint8Array => {
    class ACPKMClass extends Magma {
        encrypt(block: Uint8Array): Uint8Array { return this.encryptBlock(block); }
    }
    const cipher = new Magma(key)
    return omac_acpkm_master(ACPKMClass, cipher.encryptBlock.bind(cipher), 80, (BLOCK_SIZE * 2), BLOCK_SIZE, data);
}