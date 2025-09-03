import {
  hashPassword,
  verifyPassword,
  generateSalt,
  encryptData,
  decryptData,
  generateApiKey,
  generateSecureToken,
  validateApiKey,
  createHMAC,
  verifyHMAC,
  generateKeyPair,
  encryptWithPublicKey,
  decryptWithPrivateKey
} from '../cryptoUtils';
import { jest } from '@jest/globals';
import crypto from 'crypto';

describe('CryptoUtils', () => {
  describe('Password Hashing', () => {
    describe('hashPassword', () => {
      it('should hash password with salt', async () => {
        const password = 'testPassword123';
        const salt = 'randomSalt';
        
        const hashedPassword = await hashPassword(password, salt);
        
        expect(hashedPassword).toBeDefined();
        expect(hashedPassword).not.toBe(password);
        expect(hashedPassword.length).toBeGreaterThan(0);
      });

      it('should generate different hashes for same password with different salts', async () => {
        const password = 'testPassword123';
        const salt1 = 'salt1';
        const salt2 = 'salt2';
        
        const hash1 = await hashPassword(password, salt1);
        const hash2 = await hashPassword(password, salt2);
        
        expect(hash1).not.toBe(hash2);
      });

      it('should generate same hash for same password and salt', async () => {
        const password = 'testPassword123';
        const salt = 'consistentSalt';
        
        const hash1 = await hashPassword(password, salt);
        const hash2 = await hashPassword(password, salt);
        
        expect(hash1).toBe(hash2);
      });

      it('should handle empty password', async () => {
        const password = '';
        const salt = 'salt';
        
        const hashedPassword = await hashPassword(password, salt);
        
        expect(hashedPassword).toBeDefined();
        expect(hashedPassword.length).toBeGreaterThan(0);
      });

      it('should handle special characters in password', async () => {
        const password = '!@#$%^&*()_+-=[]{}|;:,.<>?';
        const salt = 'salt';
        
        const hashedPassword = await hashPassword(password, salt);
        
        expect(hashedPassword).toBeDefined();
        expect(hashedPassword.length).toBeGreaterThan(0);
      });

      it('should handle unicode characters', async () => {
        const password = '测试密码123🔒';
        const salt = 'salt';
        
        const hashedPassword = await hashPassword(password, salt);
        
        expect(hashedPassword).toBeDefined();
        expect(hashedPassword.length).toBeGreaterThan(0);
      });
    });

    describe('verifyPassword', () => {
      it('should verify correct password', async () => {
        const password = 'testPassword123';
        const salt = 'testSalt';
        
        const hashedPassword = await hashPassword(password, salt);
        const isValid = await verifyPassword(password, hashedPassword, salt);
        
        expect(isValid).toBe(true);
      });

      it('should reject incorrect password', async () => {
        const correctPassword = 'testPassword123';
        const incorrectPassword = 'wrongPassword';
        const salt = 'testSalt';
        
        const hashedPassword = await hashPassword(correctPassword, salt);
        const isValid = await verifyPassword(incorrectPassword, hashedPassword, salt);
        
        expect(isValid).toBe(false);
      });

      it('should reject password with wrong salt', async () => {
        const password = 'testPassword123';
        const correctSalt = 'correctSalt';
        const wrongSalt = 'wrongSalt';
        
        const hashedPassword = await hashPassword(password, correctSalt);
        const isValid = await verifyPassword(password, hashedPassword, wrongSalt);
        
        expect(isValid).toBe(false);
      });

      it('should handle case sensitivity', async () => {
        const password = 'TestPassword123';
        const wrongCasePassword = 'testpassword123';
        const salt = 'testSalt';
        
        const hashedPassword = await hashPassword(password, salt);
        const isValid = await verifyPassword(wrongCasePassword, hashedPassword, salt);
        
        expect(isValid).toBe(false);
      });
    });

    describe('generateSalt', () => {
      it('should generate random salt', () => {
        const salt1 = generateSalt();
        const salt2 = generateSalt();
        
        expect(salt1).toBeDefined();
        expect(salt2).toBeDefined();
        expect(salt1).not.toBe(salt2);
        expect(salt1.length).toBeGreaterThan(0);
      });

      it('should generate salt with custom length', () => {
        const customLength = 32;
        const salt = generateSalt(customLength);
        
        // Base64 encoding increases length, so check minimum expected length
        expect(salt.length).toBeGreaterThanOrEqual(customLength);
      });

      it('should generate different salts on multiple calls', () => {
        const salts = Array.from({ length: 10 }, () => generateSalt());
        const uniqueSalts = new Set(salts);
        
        expect(uniqueSalts.size).toBe(salts.length);
      });
    });
  });

  describe('Data Encryption', () => {
    describe('encryptData and decryptData', () => {
      it('should encrypt and decrypt data successfully', () => {
        const originalData = 'sensitive information';
        const key = 'encryption-key-32-characters-long';
        
        const encryptedData = encryptData(originalData, key);
        const decryptedData = decryptData(encryptedData, key);
        
        expect(encryptedData).not.toBe(originalData);
        expect(decryptedData).toBe(originalData);
      });

      it('should encrypt same data differently each time', () => {
        const data = 'test data';
        const key = 'encryption-key-32-characters-long';
        
        const encrypted1 = encryptData(data, key);
        const encrypted2 = encryptData(data, key);
        
        expect(encrypted1).not.toBe(encrypted2);
        
        // But both should decrypt to same original data
        expect(decryptData(encrypted1, key)).toBe(data);
        expect(decryptData(encrypted2, key)).toBe(data);
      });

      it('should handle empty data', () => {
        const data = '';
        const key = 'encryption-key-32-characters-long';
        
        const encrypted = encryptData(data, key);
        const decrypted = decryptData(encrypted, key);
        
        expect(decrypted).toBe(data);
      });

      it('should handle unicode data', () => {
        const data = '测试数据🔒💰';
        const key = 'encryption-key-32-characters-long';
        
        const encrypted = encryptData(data, key);
        const decrypted = decryptData(encrypted, key);
        
        expect(decrypted).toBe(data);
      });

      it('should handle JSON data', () => {
        const data = JSON.stringify({
          userId: 'user123',
          balance: 1000.50,
          metadata: { level: 5, verified: true }
        });
        const key = 'encryption-key-32-characters-long';
        
        const encrypted = encryptData(data, key);
        const decrypted = decryptData(encrypted, key);
        
        expect(decrypted).toBe(data);
        expect(JSON.parse(decrypted)).toEqual(JSON.parse(data));
      });

      it('should fail with wrong decryption key', () => {
        const data = 'secret data';
        const correctKey = 'correct-key-32-characters-long!';
        const wrongKey = 'wrong-key-32-characters-long!!!';
        
        const encrypted = encryptData(data, correctKey);
        
        expect(() => {
          decryptData(encrypted, wrongKey);
        }).toThrow();
      });

      it('should fail with corrupted encrypted data', () => {
        const data = 'test data';
        const key = 'encryption-key-32-characters-long';
        
        const encrypted = encryptData(data, key);
        const corruptedEncrypted = encrypted.slice(0, -5) + 'xxxxx';
        
        expect(() => {
          decryptData(corruptedEncrypted, key);
        }).toThrow();
      });
    });
  });

  describe('API Key Management', () => {
    describe('generateApiKey', () => {
      it('should generate valid API key', () => {
        const apiKey = generateApiKey();
        
        expect(apiKey).toBeDefined();
        expect(typeof apiKey).toBe('string');
        expect(apiKey.length).toBeGreaterThan(20);
        expect(apiKey).toMatch(/^[A-Za-z0-9+/]+=*$/);
      });

      it('should generate unique API keys', () => {
        const keys = Array.from({ length: 10 }, () => generateApiKey());
        const uniqueKeys = new Set(keys);
        
        expect(uniqueKeys.size).toBe(keys.length);
      });

      it('should generate API key with custom length', () => {
        const customLength = 64;
        const apiKey = generateApiKey(customLength);
        
        // Base64 encoding affects final length, but should be proportional
        expect(apiKey.length).toBeGreaterThan(customLength);
      });
    });

    describe('validateApiKey', () => {
      it('should validate correct API key format', () => {
        const validKey = generateApiKey();
        
        expect(validateApiKey(validKey)).toBe(true);
      });

      it('should reject invalid API key formats', () => {
        expect(validateApiKey('')).toBe(false);
        expect(validateApiKey('short')).toBe(false);
        expect(validateApiKey('invalid-characters-!@#$')).toBe(false);
        expect(validateApiKey('spaces in key')).toBe(false);
      });

      it('should reject null or undefined keys', () => {
        expect(validateApiKey(null as any)).toBe(false);
        expect(validateApiKey(undefined as any)).toBe(false);
      });
    });
  });

  describe('Secure Token Generation', () => {
    describe('generateSecureToken', () => {
      it('should generate secure token', () => {
        const token = generateSecureToken();
        
        expect(token).toBeDefined();
        expect(typeof token).toBe('string');
        expect(token.length).toBeGreaterThan(10);
      });

      it('should generate unique tokens', () => {
        const tokens = Array.from({ length: 10 }, () => generateSecureToken());
        const uniqueTokens = new Set(tokens);
        
        expect(uniqueTokens.size).toBe(tokens.length);
      });

      it('should generate token with custom length', () => {
        const customLength = 32;
        const token = generateSecureToken(customLength);
        
        expect(token.length).toBeGreaterThanOrEqual(customLength);
      });

      it('should generate URL-safe tokens', () => {
        const token = generateSecureToken();
        
        // Should not contain URL-unsafe characters
        expect(token).not.toMatch(/[+/=]/);
        expect(token).toMatch(/^[A-Za-z0-9_-]+$/);
      });
    });
  });

  describe('HMAC Operations', () => {
    describe('createHMAC and verifyHMAC', () => {
      it('should create and verify HMAC successfully', () => {
        const data = 'important data';
        const secret = 'shared-secret-key';
        
        const hmac = createHMAC(data, secret);
        const isValid = verifyHMAC(data, hmac, secret);
        
        expect(hmac).toBeDefined();
        expect(typeof hmac).toBe('string');
        expect(isValid).toBe(true);
      });

      it('should fail verification with wrong secret', () => {
        const data = 'important data';
        const correctSecret = 'correct-secret';
        const wrongSecret = 'wrong-secret';
        
        const hmac = createHMAC(data, correctSecret);
        const isValid = verifyHMAC(data, hmac, wrongSecret);
        
        expect(isValid).toBe(false);
      });

      it('should fail verification with modified data', () => {
        const originalData = 'original data';
        const modifiedData = 'modified data';
        const secret = 'shared-secret';
        
        const hmac = createHMAC(originalData, secret);
        const isValid = verifyHMAC(modifiedData, hmac, secret);
        
        expect(isValid).toBe(false);
      });

      it('should handle empty data', () => {
        const data = '';
        const secret = 'secret';
        
        const hmac = createHMAC(data, secret);
        const isValid = verifyHMAC(data, hmac, secret);
        
        expect(isValid).toBe(true);
      });

      it('should handle JSON data', () => {
        const data = JSON.stringify({ userId: 'user123', amount: 100 });
        const secret = 'webhook-secret';
        
        const hmac = createHMAC(data, secret);
        const isValid = verifyHMAC(data, hmac, secret);
        
        expect(isValid).toBe(true);
      });

      it('should generate different HMACs for different algorithms', () => {
        const data = 'test data';
        const secret = 'secret';
        
        const hmacSha256 = createHMAC(data, secret, 'sha256');
        const hmacSha512 = createHMAC(data, secret, 'sha512');
        
        expect(hmacSha256).not.toBe(hmacSha512);
        expect(verifyHMAC(data, hmacSha256, secret, 'sha256')).toBe(true);
        expect(verifyHMAC(data, hmacSha512, secret, 'sha512')).toBe(true);
      });
    });
  });

  describe('Asymmetric Encryption', () => {
    describe('generateKeyPair', () => {
      it('should generate RSA key pair', () => {
        const keyPair = generateKeyPair();
        
        expect(keyPair).toBeDefined();
        expect(keyPair.publicKey).toBeDefined();
        expect(keyPair.privateKey).toBeDefined();
        expect(typeof keyPair.publicKey).toBe('string');
        expect(typeof keyPair.privateKey).toBe('string');
      });

      it('should generate different key pairs', () => {
        const keyPair1 = generateKeyPair();
        const keyPair2 = generateKeyPair();
        
        expect(keyPair1.publicKey).not.toBe(keyPair2.publicKey);
        expect(keyPair1.privateKey).not.toBe(keyPair2.privateKey);
      });

      it('should generate key pair with custom key size', () => {
        const keyPair = generateKeyPair(4096);
        
        expect(keyPair.publicKey).toBeDefined();
        expect(keyPair.privateKey).toBeDefined();
        // 4096-bit keys should be longer than 2048-bit keys
        expect(keyPair.privateKey.length).toBeGreaterThan(1000);
      });
    });

    describe('encryptWithPublicKey and decryptWithPrivateKey', () => {
      it('should encrypt with public key and decrypt with private key', () => {
        const data = 'secret message';
        const keyPair = generateKeyPair();
        
        const encrypted = encryptWithPublicKey(data, keyPair.publicKey);
        const decrypted = decryptWithPrivateKey(encrypted, keyPair.privateKey);
        
        expect(encrypted).not.toBe(data);
        expect(decrypted).toBe(data);
      });

      it('should handle small data chunks', () => {
        const data = 'small';
        const keyPair = generateKeyPair();
        
        const encrypted = encryptWithPublicKey(data, keyPair.publicKey);
        const decrypted = decryptWithPrivateKey(encrypted, keyPair.privateKey);
        
        expect(decrypted).toBe(data);
      });

      it('should fail with wrong private key', () => {
        const data = 'secret message';
        const keyPair1 = generateKeyPair();
        const keyPair2 = generateKeyPair();
        
        const encrypted = encryptWithPublicKey(data, keyPair1.publicKey);
        
        expect(() => {
          decryptWithPrivateKey(encrypted, keyPair2.privateKey);
        }).toThrow();
      });

      it('should handle unicode data', () => {
        const data = '加密测试🔒';
        const keyPair = generateKeyPair();
        
        const encrypted = encryptWithPublicKey(data, keyPair.publicKey);
        const decrypted = decryptWithPrivateKey(encrypted, keyPair.privateKey);
        
        expect(decrypted).toBe(data);
      });

      it('should fail with invalid public key format', () => {
        const data = 'test data';
        const invalidKey = 'invalid-key-format';
        
        expect(() => {
          encryptWithPublicKey(data, invalidKey);
        }).toThrow();
      });

      it('should fail with invalid private key format', () => {
        const data = 'test data';
        const keyPair = generateKeyPair();
        const encrypted = encryptWithPublicKey(data, keyPair.publicKey);
        const invalidPrivateKey = 'invalid-private-key';
        
        expect(() => {
          decryptWithPrivateKey(encrypted, invalidPrivateKey);
        }).toThrow();
      });
    });
  });

  describe('Integration Tests', () => {
    it('should work with complete authentication flow', async () => {
      const password = 'userPassword123';
      const salt = generateSalt();
      
      // Hash password for storage
      const hashedPassword = await hashPassword(password, salt);
      
      // Generate API key for user
      const apiKey = generateApiKey();
      
      // Verify password during login
      const isPasswordValid = await verifyPassword(password, hashedPassword, salt);
      
      // Validate API key format
      const isApiKeyValid = validateApiKey(apiKey);
      
      expect(isPasswordValid).toBe(true);
      expect(isApiKeyValid).toBe(true);
    });

    it('should work with data encryption and HMAC verification', () => {
      const sensitiveData = JSON.stringify({
        userId: 'user123',
        balance: 1000,
        transactions: ['tx1', 'tx2']
      });
      
      const encryptionKey = 'data-encryption-key-32-chars-long';
      const hmacSecret = 'hmac-secret-key';
      
      // Encrypt sensitive data
      const encryptedData = encryptData(sensitiveData, encryptionKey);
      
      // Create HMAC for integrity
      const hmac = createHMAC(encryptedData, hmacSecret);
      
      // Verify HMAC
      const isIntegrityValid = verifyHMAC(encryptedData, hmac, hmacSecret);
      
      // Decrypt data
      const decryptedData = decryptData(encryptedData, encryptionKey);
      
      expect(isIntegrityValid).toBe(true);
      expect(decryptedData).toBe(sensitiveData);
      expect(JSON.parse(decryptedData)).toEqual(JSON.parse(sensitiveData));
    });

    it('should work with asymmetric encryption for key exchange', () => {
      // Simulate key exchange scenario
      const serverKeyPair = generateKeyPair();
      const clientKeyPair = generateKeyPair();
      expect(clientKeyPair).toBeDefined();
      
      // Client encrypts symmetric key with server's public key
      const symmetricKey = generateSecureToken(32);
      const encryptedSymmetricKey = encryptWithPublicKey(
        symmetricKey,
        serverKeyPair.publicKey
      );
      
      // Server decrypts symmetric key
      const decryptedSymmetricKey = decryptWithPrivateKey(
        encryptedSymmetricKey,
        serverKeyPair.privateKey
      );
      
      // Now both parties can use symmetric encryption
      const message = 'secure communication';
      const encryptedMessage = encryptData(message, decryptedSymmetricKey);
      const decryptedMessage = decryptData(encryptedMessage, decryptedSymmetricKey);
      
      expect(decryptedSymmetricKey).toBe(symmetricKey);
      expect(decryptedMessage).toBe(message);
    });
  });

  describe('Error Handling', () => {
    it('should handle crypto module errors gracefully', () => {
      // Mock crypto.randomBytes to throw error
      const originalRandomBytes = crypto.randomBytes;
      crypto.randomBytes = (jest.fn() as jest.MockedFunction<any>).mockImplementation(() => {
        throw new Error('Crypto module error');
      });
      
      expect(() => {
        generateSalt();
      }).toThrow('Crypto module error');
      
      // Restore original function
      crypto.randomBytes = originalRandomBytes;
    });

    it('should validate input parameters', () => {
      expect(() => {
        createHMAC(null as any, 'secret');
      }).toThrow();
      
      expect(() => {
        verifyHMAC('data', 'hmac', null as any);
      }).toThrow();
    });

    it('should handle invalid encryption parameters', () => {
      expect(() => {
        encryptData('data', '');
      }).toThrow();
      
      expect(() => {
        decryptData('encrypted', '');
      }).toThrow();
    });
  });
});