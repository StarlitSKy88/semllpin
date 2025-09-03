export declare function hashPassword(password: string, salt: string): Promise<string>;
export declare function verifyPassword(password: string, hash: string, salt: string): Promise<boolean>;
export declare function generateSalt(length?: number): string;
export declare function encryptData(data: string, key: string): string;
export declare function decryptData(encryptedData: string, key: string): string;
export declare function generateApiKey(length?: number): string;
export declare function generateSecureToken(length?: number): string;
export declare function validateApiKey(apiKey: string): boolean;
export declare function createHMAC(data: string, secret: string, algorithm?: string): string;
export declare function verifyHMAC(data: string, signature: string, secret: string, algorithm?: string): boolean;
export declare function generateKeyPair(keySize?: number): {
    publicKey: string;
    privateKey: string;
};
export declare function encryptWithPublicKey(data: string, publicKey: string): string;
export declare function decryptWithPrivateKey(encryptedData: string, privateKey: string): string;
//# sourceMappingURL=cryptoUtils.d.ts.map