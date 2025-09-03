"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.hashPassword = hashPassword;
exports.verifyPassword = verifyPassword;
exports.generateSalt = generateSalt;
exports.encryptData = encryptData;
exports.decryptData = decryptData;
exports.generateApiKey = generateApiKey;
exports.generateSecureToken = generateSecureToken;
exports.validateApiKey = validateApiKey;
exports.createHMAC = createHMAC;
exports.verifyHMAC = verifyHMAC;
exports.generateKeyPair = generateKeyPair;
exports.encryptWithPublicKey = encryptWithPublicKey;
exports.decryptWithPrivateKey = decryptWithPrivateKey;
const crypto = __importStar(require("crypto"));
const util_1 = require("util");
const scrypt = (0, util_1.promisify)(crypto.scrypt);
async function hashPassword(password, salt) {
    const derivedKey = await scrypt(password, salt, 64);
    return derivedKey.toString('hex');
}
async function verifyPassword(password, hash, salt) {
    const derivedKey = await hashPassword(password, salt);
    return derivedKey === hash;
}
function generateSalt(length = 16) {
    return crypto.randomBytes(length).toString('base64');
}
function encryptData(data, key) {
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
function decryptData(encryptedData, key) {
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
function generateApiKey(length = 32) {
    return crypto.randomBytes(length).toString('base64');
}
function generateSecureToken(length = 32) {
    return crypto.randomBytes(length).toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}
function validateApiKey(apiKey) {
    if (!apiKey || typeof apiKey !== 'string') {
        return false;
    }
    return /^[A-Za-z0-9+/]+=*$/.test(apiKey) && apiKey.length > 20;
}
function createHMAC(data, secret, algorithm = 'sha256') {
    if (!data || !secret) {
        throw new Error('Data and secret are required');
    }
    return crypto.createHmac(algorithm, secret).update(data).digest('hex');
}
function verifyHMAC(data, signature, secret, algorithm = 'sha256') {
    if (!data || !signature || !secret) {
        throw new Error('Data, signature and secret are required');
    }
    const expectedSignature = createHMAC(data, secret, algorithm);
    return crypto.timingSafeEqual(Buffer.from(signature, 'hex'), Buffer.from(expectedSignature, 'hex'));
}
function generateKeyPair(keySize = 2048) {
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
function encryptWithPublicKey(data, publicKey) {
    const encrypted = crypto.publicEncrypt(publicKey, Buffer.from(data, 'utf8'));
    return encrypted.toString('base64');
}
function decryptWithPrivateKey(encryptedData, privateKey) {
    const decrypted = crypto.privateDecrypt(privateKey, Buffer.from(encryptedData, 'base64'));
    return decrypted.toString('utf8');
}
//# sourceMappingURL=cryptoUtils.js.map