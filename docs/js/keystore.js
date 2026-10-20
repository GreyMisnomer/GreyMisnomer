/**
 * GreyMisnomer Sovereign Client Enclave — Keystore Engine
 * Implements self-sovereign key encryption and decryption using native W3C WebCrypto API.
 * Standards: PBKDF2-HMAC-SHA256 (100,000 iterations) + AES-256-GCM (128-bit MAC).
 * Compatible with Bitcoin BIP-38 and Ethereum Keystore V3 security principles.
 */

const PBKDF2_ITERATIONS = 100000;
const SALT_BYTE_LENGTH = 16;
const IV_BYTE_LENGTH = 12;
const TAG_BYTE_LENGTH = 16;

/**
 * Converts a Uint8Array into a lowercase hex string.
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function bytesToHex(bytes) {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Converts a hex string into a Uint8Array.
 * @param {string} hex
 * @returns {Uint8Array}
 */
export function hexToBytes(hex) {
  if (typeof hex !== 'string') {
    throw new TypeError('Hex argument must be a string');
  }
  const cleanHex = hex.trim().replace(/^0x/i, '');
  if (cleanHex.length % 2 !== 0) {
    throw new Error('Invalid hex string length');
  }
  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    const byte = parseInt(cleanHex.substring(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) {
      throw new Error(`Invalid hex character at index ${i * 2}`);
    }
    bytes[i] = byte;
  }
  return bytes;
}

/**
 * Generates a unique UUIDv4 string.
 * @returns {string}
 */
export function generateUuid() {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }
  // Fallback RFC-4122 v4 UUID generator using crypto.getRandomValues
  const rnd = new Uint8Array(16);
  crypto.getRandomValues(rnd);
  rnd[6] = (rnd[6] & 0x0f) | 0x40;
  rnd[8] = (rnd[8] & 0x3f) | 0x80;
  const h = bytesToHex(rnd);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

/**
 * Encrypts a 32-byte Ed25519 secret key hex string with a user passphrase.
 * Returns an encrypted `.gmkey` keystore envelope.
 *
 * @param {string} secretKeyHex - 64-character lowercase secret key hex
 * @param {string} passphrase - User-chosen passphrase
 * @param {Object} metadata - Metadata fields { id, label, role, pubkey }
 * @returns {Promise<Object>} The encrypted .gmkey keystore object
 */
export async function encryptSecretKey(secretKeyHex, passphrase, metadata = {}) {
  if (!secretKeyHex || typeof secretKeyHex !== 'string') {
    throw new Error('Secret key must be a valid hex string');
  }
  const cleanKey = secretKeyHex.trim().toLowerCase();
  if (cleanKey.length !== 64) {
    throw new Error('Secret key hex must be exactly 64 characters (32 bytes)');
  }
  if (!passphrase || typeof passphrase !== 'string') {
    throw new Error('Passphrase must be a non-empty string');
  }

  const enc = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTE_LENGTH));
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTE_LENGTH));

  // 1. Import passphrase as raw key material for PBKDF2
  const baseKey = await crypto.subtle.importKey(
    'raw',
    enc.encode(passphrase),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );

  // 2. Derive 256-bit AES-GCM symmetric key
  const derivedKey = await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations: PBKDF2_ITERATIONS,
      hash: 'SHA-256'
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );

  // 3. Encrypt the secret key hex string
  const plaintextBytes = enc.encode(cleanKey);
  const cipherBuffer = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv,
      tagLength: 128
    },
    derivedKey,
    plaintextBytes
  );

  // In WebCrypto AES-GCM, the last 16 bytes of cipherBuffer is the authentication tag
  const cipherBytes = new Uint8Array(cipherBuffer);
  const ciphertextBytes = cipherBytes.slice(0, -TAG_BYTE_LENGTH);
  const macBytes = cipherBytes.slice(-TAG_BYTE_LENGTH);

  const keyId = metadata.id || generateUuid();

  const gmkey = {
    version: 1,
    id: keyId,
    label: metadata.label || 'Sovereign Participant',
    role: metadata.role || 'Participant',
    pubkey: metadata.pubkey || '',
    created_at: new Date().toISOString(),
    crypto: {
      cipher: 'aes-256-gcm',
      ciphertext: bytesToHex(ciphertextBytes),
      cipherparams: {
        iv: bytesToHex(iv)
      },
      kdf: 'pbkdf2',
      kdfparams: {
        iterations: PBKDF2_ITERATIONS,
        hash: 'SHA-256',
        salt: bytesToHex(salt)
      },
      mac: bytesToHex(macBytes)
    }
  };

  return gmkey;
}

/**
 * Decrypts a `.gmkey` keystore envelope using the passphrase.
 *
 * @param {Object} gmkeyObj - The parsed .gmkey keystore object
 * @param {string} passphrase - User passphrase
 * @returns {Promise<string>} The decrypted 64-character secret key hex string
 */
export async function decryptSecretKey(gmkeyObj, passphrase) {
  if (!gmkeyObj || typeof gmkeyObj !== 'object') {
    throw new Error('Invalid keystore object');
  }
  if (gmkeyObj.version !== 1) {
    throw new Error(`Unsupported keystore version: ${gmkeyObj.version}. Only version 1 is supported.`);
  }
  if (!gmkeyObj.crypto || typeof gmkeyObj.crypto !== 'object') {
    throw new Error('Malformed keystore: missing crypto block');
  }
  if (!passphrase || typeof passphrase !== 'string') {
    throw new Error('Passphrase must be a non-empty string');
  }

  const { crypto: c } = gmkeyObj;
  if (c.cipher !== 'aes-256-gcm') {
    throw new Error(`Unsupported cipher: ${c.cipher}`);
  }
  if (c.kdf !== 'pbkdf2') {
    throw new Error(`Unsupported KDF: ${c.kdf}`);
  }

  const enc = new TextEncoder();
  const dec = new TextDecoder();

  const salt = hexToBytes(c.kdfparams.salt);
  const iv = hexToBytes(c.cipherparams.iv);
  const ciphertextBytes = hexToBytes(c.ciphertext);
  const macBytes = hexToBytes(c.mac);
  const iterations = c.kdfparams.iterations || PBKDF2_ITERATIONS;
  const hash = c.kdfparams.hash || 'SHA-256';

  // 1. Import passphrase as raw base key
  const baseKey = await crypto.subtle.importKey(
    'raw',
    enc.encode(passphrase),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );

  // 2. Derive 256-bit AES-GCM key
  const derivedKey = await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations,
      hash
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );

  // 3. Recombine ciphertext + authentication tag for WebCrypto
  const combinedBuffer = new Uint8Array(ciphertextBytes.length + macBytes.length);
  combinedBuffer.set(ciphertextBytes);
  combinedBuffer.set(macBytes, ciphertextBytes.length);

  try {
    const decryptedBuffer = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv,
        tagLength: 128
      },
      derivedKey,
      combinedBuffer
    );

    const secretKeyHex = dec.decode(decryptedBuffer).trim().toLowerCase();
    if (secretKeyHex.length !== 64) {
      throw new Error('Decrypted secret key length mismatch');
    }
    return secretKeyHex;
  } catch (err) {
    if (err.name === 'OperationError' || err.message?.includes('tag')) {
      throw new Error('Authentication failed: incorrect passphrase or corrupted keystore');
    }
    throw err;
  }
}

// Attach to global window if available for script-tag access
if (typeof window !== 'undefined') {
  window.GreyMisnomerKeystore = {
    bytesToHex,
    hexToBytes,
    generateUuid,
    encryptSecretKey,
    decryptSecretKey
  };
}
