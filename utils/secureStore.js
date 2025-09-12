/**
 * src/utils/cryptoHelpers.js
 *
 * Hardened crypto helpers:
 * - deriveKey returns { keyBuf (Uint8Array), saltHex }
 * - encryptAESGCM / decryptAESGCM accept keyBuf or keyHex
 * - decryptAESGCM throws on failure
 * - helpers for hex <-> Uint8Array and zeroing sensitive buffers
 *
 * IMPORTANT: Verify react-native-simple-crypto API signatures (Argon2, HMAC.pbkdf2, AES.encrypt/decrypt)
 */

import RNSimpleCrypto from "react-native-simple-crypto";

const RANDOM_SALT_BYTES = 16;
const IV_BYTES = 12;
const KEY_LENGTH_BYTES = 32; // 256 bits
const AES_TAG_BYTES = 16; // typical GCM tag length

// --- Secure helpers (exported) ---
export function hexToUint8(hex) {
  if (!hex) return null;
  const len = Math.floor(hex.length / 2);
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

export function uint8ToHex(u8) {
  if (!u8) return "";
  return Array.from(u8).map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function zeroBuffer(u8) {
  if (!u8) return;
  if (typeof u8.fill === "function") {
    u8.fill(0);
  } else {
    for (let i = 0; i < u8.length; i++) u8[i] = 0;
  }
}

async function randomBytesHex(bytes) {
  let arr = RNSimpleCrypto.utils.randomBytes(bytes);
  if (arr && typeof arr.then === "function") arr = await arr;
  return RNSimpleCrypto.utils.convertArrayBufferToHex(arr);
}

function utf8ToHex(str) {
  if (!str) return "";
  const enc = new TextEncoder();
  const bytes = enc.encode(String(str));
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function validateHexLength(hex, expectedBytes) {
  return typeof hex === "string" && hex.length === expectedBytes * 2;
}

/**
 * deriveKey(password, saltHex?)
 * - returns { keyBuf (Uint8Array), saltHex }
 * - callers should zeroBuffer(keyBuf) after use
 */
export async function deriveKey(password, saltHex = null) {
  if (typeof password !== "string" || password.length === 0) {
    throw new Error("deriveKey: password required");
  }

  const salt = saltHex ?? (await randomBytesHex(RANDOM_SALT_BYTES));
  let keyHex = null;

  // Argon2 conservative configs (units typical KiB in many libs)
  const argonConfigs = [
    { iterations: 3, memory: 32768, parallelism: 1 }, // 32 MiB
    { iterations: 3, memory: 16384, parallelism: 1 }, // 16 MiB
  ];

  if (RNSimpleCrypto.Argon2 && typeof RNSimpleCrypto.Argon2.hash === "function") {
    for (const cfg of argonConfigs) {
      try {
        keyHex = await RNSimpleCrypto.Argon2.hash(password, salt, {
          iterations: cfg.iterations,
          memory: cfg.memory,
          parallelism: cfg.parallelism,
          hashLength: KEY_LENGTH_BYTES,
          mode: "argon2id",
        });
        if (!validateHexLength(keyHex, KEY_LENGTH_BYTES)) {
          keyHex = null;
          continue;
        }
        break;
      } catch {
        // try next
      }
    }
  }

  if (!keyHex) {
    if (!(RNSimpleCrypto.HMAC && typeof RNSimpleCrypto.HMAC.pbkdf2 === "function")) {
      throw new Error("deriveKey: No KDF available");
    }
    const iterations = 150000; // conservative for mobile; tune after benchmarking
    const saltBuf = hexToUint8(salt);
    try {
      // try with ArrayBuffer/Uint8Array salt, fallback to hex
      keyHex = await RNSimpleCrypto.HMAC.pbkdf2(password, saltBuf, iterations, KEY_LENGTH_BYTES, "SHA512");
    } catch {
      keyHex = await RNSimpleCrypto.HMAC.pbkdf2(password, salt, iterations, KEY_LENGTH_BYTES, "SHA512");
    }
    if (!validateHexLength(keyHex, KEY_LENGTH_BYTES)) {
      throw new Error("deriveKey: KDF produced unexpected key length");
    }
  }

  const keyBuf = hexToUint8(keyHex);
  keyHex = null; // drop string reference
  return { keyBuf, saltHex: salt };
}

/**
 * encryptAESGCM(key (Uint8Array or hex string), plaintext string, aad string|null)
 * Returns { cipherHex, ivHex, aadHex }
 *
 * Note: assumes AES.encrypt returns hex of ciphertext+tag or ciphertext depending on lib.
 * We store cipherHex and ivHex and aadHex. If library returns tag separately, adjust here.
 */
export async function encryptAESGCM(key, plaintext, aad = null) {
  if (!key || typeof plaintext !== "string") throw new Error("encryptAESGCM: key and plaintext required");

  const ivHex = await randomBytesHex(IV_BYTES);
  const aadHex = aad ? (typeof aad === "string" && /^[0-9a-fA-F]+$/.test(aad) ? aad : utf8ToHex(String(aad))) : null;

  let usedBuf = null;
  let usedHex = null;
  try {
    if (key instanceof Uint8Array || (key && key.buffer && typeof key.byteLength === "number")) {
      usedBuf = key instanceof Uint8Array ? key : new Uint8Array(key);
      // Try to call AES.encrypt with ArrayBuffer if supported
      try {
        const arrBuf = usedBuf.buffer;
        const cipherHex = await RNSimpleCrypto.AES.encrypt(plaintext, arrBuf, ivHex, aadHex);
        return { cipherHex, ivHex, aadHex };
      } catch {
        usedHex = uint8ToHex(usedBuf);
      }
    } else if (typeof key === "string") {
      usedHex = key;
    } else {
      throw new Error("encryptAESGCM: unsupported key type");
    }

    const cipherHex = await RNSimpleCrypto.AES.encrypt(plaintext, usedHex, ivHex, aadHex);
    return { cipherHex, ivHex, aadHex };
  } finally {
    if (usedBuf) zeroBuffer(usedBuf);
    usedHex = null;
  }
}

/**
 * decryptAESGCM(key (Uint8Array or hex string), cipherHex, ivHex, aad?)
 * - Returns plaintext on success
 * - Throws error on failure (wrong key or tamper)
 */
export async function decryptAESGCM(key, cipherHex, ivHex, aad = null) {
  if (!key || !cipherHex || !ivHex) {
    console.warn("decryptAESGCM: invalid parameters");
    return null;
  }

  const aadHex = aad ? (typeof aad === "string" && /^[0-9a-fA-F]+$/.test(aad) ? aad : utf8ToHex(String(aad))) : null;

  let usedBuf = null;
  let usedHex = null;
  try {
    if (key instanceof Uint8Array || (key && key.buffer && typeof key.byteLength === "number")) {
      usedBuf = key instanceof Uint8Array ? key : new Uint8Array(key);
      try {
        const arrBuf = usedBuf.buffer;
        const plain = await RNSimpleCrypto.AES.decrypt(cipherHex, arrBuf, ivHex, aadHex);
        return plain;
      } catch {
        usedHex = uint8ToHex(usedBuf);
      }
    } else if (typeof key === "string") {
      usedHex = key;
    } else {
      throw new Error("decryptAESGCM: unsupported key type");
    }

    const plain = await RNSimpleCrypto.AES.decrypt(cipherHex, usedHex, ivHex, aadHex);
    return plain;
  } catch (err) {
    // Important: throw to let caller detect tampering / wrong key
    // Avoid leaking internal error details
    throw new Error("Decryption failed (wrong key or data tampering)");
  } finally {
    if (usedBuf) zeroBuffer(usedBuf);
    usedHex = null;
  }
}
