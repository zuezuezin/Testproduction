/**
 * src/utils/cryptoHelpers.js
 *
 * Hardened crypto helpers:
 * - await randomBytes (handles sync/async return)
 * - safe hex <-> ArrayBuffer conversions
 * - deriveKey: Argon2id attempts with safer defaults + PBKDF2 fallback
 * - validate derived key length
 * - encryptAESGCM / decryptAESGCM support optional AAD (string or hex)
 *
 * NOTES / ACTIONS FOR QA:
 * - Run unit tests on target devices to confirm:
 *   * RNSimpleCrypto.Argon2.hash memory units (KiB vs bytes)
 *   * RNSimpleCrypto.HMAC.pbkdf2 salt input types accepted
 *   * RNSimpleCrypto.AES.encrypt/decrypt return formats (cipher+tag)
 * - Tune Argon2 memory parameters after microbenchmarking low-end devices.
 */

import RNSimpleCrypto from "react-native-simple-crypto";

const RANDOM_SALT_BYTES = 16;
const IV_BYTES = 12;
const KEY_LENGTH_BYTES = 32; // 32 bytes = 256 bits

// Helper: handle randomBytes returning ArrayBuffer or Promise<ArrayBuffer>
async function randomBytesHex(bytes) {
  let arr = RNSimpleCrypto.utils.randomBytes(bytes);
  if (arr && typeof arr.then === "function") arr = await arr;
  return RNSimpleCrypto.utils.convertArrayBufferToHex(arr);
}

function utf8ToHex(str) {
  if (!str) return "";
  const encoder = new TextEncoder();
  const bytes = encoder.encode(str);
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function hexToArrayBuffer(hex) {
  if (!hex) return null;
  if (RNSimpleCrypto.utils && typeof RNSimpleCrypto.utils.convertHexToArrayBuffer === "function") {
    try {
      return RNSimpleCrypto.utils.convertHexToArrayBuffer(hex);
    } catch {
      // fall back to manual
    }
  }
  const len = hex.length / 2;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  return bytes.buffer;
}

function validateHexLength(hex, expectedBytes) {
  return typeof hex === "string" && hex.length === expectedBytes * 2;
}

/**
 * deriveKey(password, saltHex?, keyLenBytes?)
 * Returns { keyHex, saltHex }
 *
 * Security notes:
 * - Argon2 memory units vary; default here uses conservative KiB-style values.
 * - Benchmark & tune for lowest-target device before shipping.
 */
export async function deriveKey(password, saltHex = null, keyLenBytes = KEY_LENGTH_BYTES) {
  if (typeof password !== "string" || password.length === 0) {
    throw new Error("deriveKey: password required");
  }

  const salt = saltHex ?? (await randomBytesHex(RANDOM_SALT_BYTES));
  let keyHex = null;

  // Safer default Argon2 memory settings (assume memory is KiB; adjust if your lib uses bytes)
  // Order: 64MiB -> 32MiB -> 16MiB
  const argonConfigs = [
    { iterations: 3, memory: 65536, parallelism: 2 }, // 64 MiB (KiB units)
    { iterations: 3, memory: 32768, parallelism: 2 }, // 32 MiB
    { iterations: 4, memory: 16384, parallelism: 1 }, // 16 MiB
  ];

  if (RNSimpleCrypto.Argon2 && typeof RNSimpleCrypto.Argon2.hash === "function") {
    for (let i = 0; i < argonConfigs.length; i++) {
      const cfg = argonConfigs[i];
      try {
        // signature: Argon2.hash(password, salt, options)
        keyHex = await RNSimpleCrypto.Argon2.hash(password, salt, {
          iterations: cfg.iterations,
          memory: cfg.memory,
          parallelism: cfg.parallelism,
          hashLength: keyLenBytes,
          mode: "argon2id",
        });
        // validate length (hex)
        if (!validateHexLength(keyHex, keyLenBytes)) {
          keyHex = null;
          continue;
        }
        break;
      } catch (err) {
        // minimal logging only
        // eslint-disable-next-line no-console
        console.warn("deriveKey: Argon2 attempt failed; trying fallback");
      }
    }
  }

  if (!keyHex) {
    // PBKDF2-SHA512 fallback
    if (!(RNSimpleCrypto.HMAC && typeof RNSimpleCrypto.HMAC.pbkdf2 === "function")) {
      throw new Error("deriveKey: No KDF available");
    }
    const iterations = 200000;
    // try ArrayBuffer salt first
    const saltBuf = hexToArrayBuffer(salt);
    try {
      keyHex = await RNSimpleCrypto.HMAC.pbkdf2(password, saltBuf, iterations, keyLenBytes, "SHA512");
    } catch {
      // try salt string fallback
      keyHex = await RNSimpleCrypto.HMAC.pbkdf2(password, salt, iterations, keyLenBytes, "SHA512");
    }
    if (!validateHexLength(keyHex, keyLenBytes)) {
      throw new Error("deriveKey: KDF produced unexpected key length");
    }
  }

  return { keyHex, saltHex: salt };
}

/**
 * encryptAESGCM(keyHex, plaintext, aad? (string|hex|null))
 * - Accepts aad as UTF8 string or hex string. Stores and returns aadHex.
 * Returns { cipherHex, ivHex, aadHex }
 *
 * Note: verify that RNSimpleCrypto.AES.encrypt returns ciphertext including auth-tag.
 * If your version returns separate tag, update callers to store tagHex too.
 */
export async function encryptAESGCM(keyHex, plaintext, aad = null) {
  if (!keyHex || typeof plaintext !== "string") throw new Error("encryptAESGCM: keyHex and plaintext required");

  const ivHex = await randomBytesHex(IV_BYTES);
  let aadHex = null;
  if (aad) {
    // if aad looks like hex (even length and hex chars) accept, otherwise convert utf8 to hex
    const isHex = typeof aad === "string" && /^[0-9a-fA-F]+$/.test(aad) && (aad.length % 2 === 0);
    aadHex = isHex ? aad : utf8ToHex(String(aad));
  }

  let cipherHex;
  try {
    // try AAD-aware API first
    cipherHex = await RNSimpleCrypto.AES.encrypt(plaintext, keyHex, ivHex, aadHex);
  } catch {
    // fallback without AAD param
    cipherHex = await RNSimpleCrypto.AES.encrypt(plaintext, keyHex, ivHex);
  }

  return { cipherHex, ivHex, aadHex };
}

/**
 * decryptAESGCM(keyHex, cipherHex, ivHex, aadHex?)
 * Returns plaintext or null on failure.
 */
export async function decryptAESGCM(keyHex, cipherHex, ivHex, aadHex = null) {
  if (!keyHex || !cipherHex || !ivHex) return null;
  try {
    let plain;
    try {
      plain = await RNSimpleCrypto.AES.decrypt(cipherHex, keyHex, ivHex, aadHex);
    } catch {
      plain = await RNSimpleCrypto.AES.decrypt(cipherHex, keyHex, ivHex);
    }
    return plain;
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error("decryptAESGCM: decryption failed");
    return null;
  }
}