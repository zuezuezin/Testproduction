/**
 * src/utils/secureStore.js
 *
 * Hardened SecureStore wrapper:
 * - Only setItemAsync passes options (many expo versions don't accept options on getItemAsync)
 * - Defensive try/catch
 * - Prevents storing sensitive keys on web
 * - Sanitizes legacy localStorage keys on web (best-effort)
 *
 * Verify expo-secure-store version: option name may be 'keychainAccessible' or 'accessible'.
 */

import { Platform } from "react-native";
import * as SecureStore from "expo-secure-store";

const isWeb = Platform.OS === "web";

const SENSITIVE_PREFIXES = ["WALLET_ENC_", "WALLET_", "MNEMONIC_", "MNEMONIC_ENC_"];
const SENSITIVE_KEYS = ["WALLET_LIST", "PHRASE_CONFIRMED"];

const isSensitiveKey = (key) => {
  if (!key) return false;
  for (const p of SENSITIVE_PREFIXES) if (key.startsWith(p)) return true;
  return SENSITIVE_KEYS.includes(key);
};

// Sanitize legacy sensitive keys from localStorage (best-effort)
(function sanitizeLocalStorageOnWeb() {
  if (isWeb && typeof localStorage !== "undefined") {
    try {
      const toRemove = [];
      for (let i = 0; i < localStorage.length; i++) {
        const k = localStorage.key(i);
        if (isSensitiveKey(k)) toRemove.push(k);
      }
      for (const k of toRemove) {
        // eslint-disable-next-line no-console
        console.warn(`secureStore: Removing sensitive localStorage key on web: ${k}`);
        localStorage.removeItem(k);
      }
    } catch {
      // ignore restricted environments
    }
  }
})();

// Options for setItemAsync: verify name with your expo SDK
const SECURESTORE_SET_OPTIONS = {
  keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
};

export const setItemAsync = async (key, value) => {
  if (!key) throw new Error("setItemAsync: key required");

  if (isWeb) {
    if (isSensitiveKey(key)) {
      throw new Error(`Refusing to store sensitive key "${key}" in localStorage on web.`);
    }
    try {
      localStorage.setItem(key, value);
    } catch (e) {
      // eslint-disable-next-line no-console
      console.warn("secureStore: localStorage.setItem failed");
      throw e;
    }
    return;
  }

  try {
    await SecureStore.setItemAsync(key, value, SECURESTORE_SET_OPTIONS);
  } catch (e) {
    // eslint-disable-next-line no-console
    console.warn("secureStore: SecureStore.setItemAsync failed");
    throw e;
  }
};

export const getItemAsync = async (key) => {
  if (!key) return null;
  if (isWeb) {
    if (isSensitiveKey(key)) return null;
    try {
      return localStorage.getItem(key);
    } catch {
      // eslint-disable-next-line no-console
      console.warn("secureStore: localStorage.getItem failed");
      return null;
    }
  }

  try {
    // Many expo-secure-store versions accept only (key). Do NOT pass options here.
    return await SecureStore.getItemAsync(key);
  } catch (e) {
    // eslint-disable-next-line no-console
    console.warn("secureStore: SecureStore.getItemAsync failed");
    return null;
  }
};

export const deleteItemAsync = async (key) => {
  if (!key) return;
  if (isWeb) {
    if (typeof localStorage !== "undefined") {
      try {
        localStorage.removeItem(key);
      } catch {
        // eslint-disable-next-line no-console
        console.warn("secureStore: localStorage.removeItem failed");
      }
    }
    return;
  }
  try {
    await SecureStore.deleteItemAsync(key);
  } catch {
    // eslint-disable-next-line no-console
    console.warn("secureStore: SecureStore.deleteItemAsync failed");
  }
};