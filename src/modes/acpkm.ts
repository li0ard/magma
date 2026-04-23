import { BLOCK_SIZE, Magma } from "../index.js";
import { ctr_acpkm, acpkmDerivation as acpkmDerivation_, acpkmDerivationMaster as acpkmDerivationMaster_, omac_acpkm_master, type TArg, type TRet } from "@li0ard/gost3413";

/**
 * Encrypts data using the Counter with Advance Cryptographic Prolongation of Key Material (CTR-ACPKM) mode with Magma cipher.
 * 
 * @param key Encryption key
 * @param data Data to be encrypted
 * @param iv Initialization vector
 */
export const encryptCTR_ACPKM = (key: TArg<Uint8Array>, data: TArg<Uint8Array>, iv: TArg<Uint8Array>): TRet<Uint8Array> => {
    class ACPKMClass extends Magma {
        encrypt(block: TArg<Uint8Array>): TRet<Uint8Array> { return this.encryptBlock(block); }
    }
    
    const cipher = new Magma(key);
    return ctr_acpkm(ACPKMClass, cipher.encryptBlock.bind(cipher), 16, BLOCK_SIZE, data, iv);
}

/**
 * Decrypts data using Counter with Advance Cryptographic Prolongation of Key Material (CTR-ACPKM) mode with Magma cipher.
 * 
 * @param key Encryption key
 * @param data Data to be decrypted
 * @param iv Initialization vector
 */
export const decryptCTR_ACPKM = encryptCTR_ACPKM;

/**
 * ACPKM key derivation
 * @param key Encryption key
 */
export const acpkmDerivation = (key: TArg<Uint8Array>): TRet<Uint8Array> => {
    const cipher = new Magma(key);
    return acpkmDerivation_(cipher.encryptBlock.bind(cipher), BLOCK_SIZE);
}

/**
 * ACPKM master key derivation
 * @param key Encryption key
 * @param keySize Length of key material
 */
export const acpkmDerivationMaster = (key: TArg<Uint8Array>, keySize: number): TRet<Uint8Array> => {
    class ACPKMClass extends Magma {
        encrypt(block: TArg<Uint8Array>): TRet<Uint8Array> { return this.encryptBlock(block); }
    }

    const cipher = new Magma(key);
    return acpkmDerivationMaster_(ACPKMClass, cipher.encryptBlock.bind(cipher), 80, BLOCK_SIZE, keySize * 40);
}

/**
 * Compute MAC with Advance Cryptographic Prolongation of Key Material (OMAC-ACPKM) with Magma cipher
 * @param key Encryption key
 * @param data Input data
 */
export const omac_ACPKM = (key: TArg<Uint8Array>, data: TArg<Uint8Array>): TRet<Uint8Array> => {
    class ACPKMClass extends Magma {
        encrypt(block: TArg<Uint8Array>): TRet<Uint8Array> { return this.encryptBlock(block); }
    }
    const cipher = new Magma(key);
    return omac_acpkm_master(ACPKMClass, cipher.encryptBlock.bind(cipher), 80, 16, BLOCK_SIZE, data);
}