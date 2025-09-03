import * as crypto from 'crypto';
import { promisify } from 'util';

const scrypt = promisify(crypto.scrypt);

/**
 * Hash password with salt using scrypt
 */
export async function hashPassword(password: string, salt: string): Promise<string> {
  const derivedKey = await scrypt(password, salt, 64) as Buffer;
  return derivedKey.toString('hex');
}

/**
 * Verify password against hash
 */
export async function verifyPassword(
  password: string,
  hash: string,
  salt: string,
): Promise<boolean> {
  const derivedKey = await hashPassword(password, salt);
  return derivedKey === hash;
}

/**
 * Generate random salt
 */
export function generateSalt(length: number = 16): string {
  return crypto.randomBytes(length).toString('base64');
}

/**
 * Encrypt data using AES-256-CBC
 */
export function encryptData(data: string, key: string): string {
  if (!key) {
    throw new Error('Encryption key is required');
  }

  const algorithm = 'aes-256-cbc';
  const iv = crypto.randomBytes(16);

  const cipher = crypto.createCipher(algorithm, key);

  let encrypted = cipher.update(data, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  return `${iv.toString('hex')}:${encrypted}`;
}

/**
 * Decrypt data using AES-256-CBC
 */
export function decryptData(encryptedData: string, key: string): string {
  if (!key) {
    throw new Error('Decryption key is required');
  }

  const algorithm = 'aes-256-cbc';
  const [ivHex, encrypted] = encryptedData.split(':');

  if (!ivHex || !encrypted) {
    throw new Error('Invalid encrypted data format');
  }

  const decipher = crypto.createDecipher(algorithm, key);

  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');

  return decrypted;
}

/**
 * Generate API key
 */
export function generateApiKey(length: number = 32): string {
  return crypto.randomBytes(length).toString('base64');
}

/**
 * Generate secure token
 */
export function generateSecureToken(length: number = 32): string {
  return crypto.randomBytes(length).toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

/**
 * Validate API key format
 */
export function validateApiKey(apiKey: string): boolean {
  if (!apiKey || typeof apiKey !== 'string') {
    return false;
  }
  return /^[A-Za-z0-9+/]+=*$/.test(apiKey) && apiKey.length > 20;
}

/**
 * Create HMAC signature
 */
export function createHMAC(data: string, secret: string, algorithm: string = 'sha256'): string {
  if (!data || !secret) {
    throw new Error('Data and secret are required');
  }
  return crypto.createHmac(algorithm, secret).update(data).digest('hex');
}

/**
 * Verify HMAC signature
 */
export function verifyHMAC(data: string, signature: string, secret: string, algorithm: string = 'sha256'): boolean {
  if (!data || !signature || !secret) {
    throw new Error('Data, signature and secret are required');
  }
  const expectedSignature = createHMAC(data, secret, algorithm);
  return crypto.timingSafeEqual(
    Buffer.from(signature, 'hex'),
    Buffer.from(expectedSignature, 'hex'),
  );
}

/**
 * Generate RSA key pair
 */
export function generateKeyPair(keySize: number = 2048): { publicKey: string; privateKey: string } {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: keySize,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem',
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem',
    },
  });

  return { publicKey, privateKey };
}

/**
 * Encrypt with RSA public key
 */
export function encryptWithPublicKey(data: string, publicKey: string): string {
  const encrypted = crypto.publicEncrypt(publicKey, Buffer.from(data, 'utf8'));
  return encrypted.toString('base64');
}

/**
 * Decrypt with RSA private key
 */
export function decryptWithPrivateKey(encryptedData: string, privateKey: string): string {
  const decrypted = crypto.privateDecrypt(privateKey, Buffer.from(encryptedData, 'base64'));
  return decrypted.toString('utf8');
}
