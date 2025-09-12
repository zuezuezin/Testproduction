/**
 * src/context/WalletContext.js
 *
 * Hardened WalletContext:
 * - persisted per-wallet failed-unlock counters (SecureStore) to prevent easy reset by restarting app
 * - binds AAD (walletId + version) into AES-GCM encryption/decryption
 * - awaits random bytes correctly when generating IDs / hardware keys
 * - avoids global localStorage.clear(); uses selective deletion
 * - best-effort zeroing of sensitive variables
 *
 * TESTING: after integrating, run the QA checklist:
 * - deriveKey timing & length tests on low-end device
 * - AES encrypt/decrypt + tamper detection
 * - hardware-key flows on physical devices (react-native-keychain + native rebuild)
 * - release build tests (Hermes + ProGuard + obfuscation)
 */

import React, { createContext, useState, useEffect, useContext, useCallback, useMemo } from "react";
import { ethers } from "ethers";
import { setItemAsync, getItemAsync, deleteItemAsync } from "../utils/secureStore";
import * as SecureStore from "expo-secure-store";
import { AppState } from "react-native";
import { deriveKey, encryptAESGCM, decryptAESGCM } from "../utils/cryptoHelpers";
import * as ScreenCapture from "expo-screen-capture";

let Keychain = null;
try {
  // eslint-disable-next-line global-require
  Keychain = require("react-native-keychain");
} catch {
  Keychain = null;
}

const WALLET_FAILED_UNLOCKS_PREFIX = "FAILED_UNLOCKS_"; // persisted per wallet
const WALLET_LAST_FAILED_AT_PREFIX = "LAST_FAILED_AT_";

const WalletContext = createContext();

export const WalletProvider = ({ children }) => {
  const [wallets, setWallets] = useState([]);
  const [currentWallet, setCurrentWallet] = useState(null);
  const [monBalance, setMonBalance] = useState("0.0");
  const [loading, setLoading] = useState(true);
  const [hasBackedUp, setHasBackedUp] = useState(false);
  const [isUnlocked, setIsUnlocked] = useState(false);
  const [appState, setAppState] = useState(AppState.currentState);

  // tempWalletData only contains encrypted blob + metadata (no plaintext)
  const [tempWalletData, setTempWalletData] = useState(null);

  // in-memory mirrors of persisted counters for quick access
  const [failedUnlocksMap, setFailedUnlocksMap] = useState({}); // { walletId: n }
  const [lastFailedAtMap, setLastFailedAtMap] = useState({}); // { walletId: timestamp }

  const RPC_URL = "https://testnet-rpc.monad.xyz";
  const provider = useMemo(() => new ethers.JsonRpcProvider(RPC_URL), []);

  const [isDeviceCompromised, setIsDeviceCompromised] = useState(false);

  // Load persisted failed-unlock counters on init
  useEffect(() => {
    (async () => {
      try {
        const wlJson = await getItemAsync("WALLET_LIST");
        const list = wlJson ? JSON.parse(wlJson) : [];
        for (const w of list) {
          const f = await getItemAsync(`${WALLET_FAILED_UNLOCKS_PREFIX}${w.id}`);
          const at = await getItemAsync(`${WALLET_LAST_FAILED_AT_PREFIX}${w.id}`);
          setFailedUnlocksMap((m) => ({ ...m, [w.id]: f ? parseInt(f, 10) : 0 }));
          setLastFailedAtMap((m) => ({ ...m, [w.id]: at ? parseInt(at, 10) : null }));
        }
      } catch {
        // ignore
      }
    })();
  }, []);

  // Jailbreak/root detection (best-effort)
  useEffect(() => {
    (async () => {
      try {
        // eslint-disable-next-line global-require
        const JailMonkey = require("jail-monkey");
        if (JailMonkey && (JailMonkey.isJailBroken() || JailMonkey.isOnSimulator())) {
          setIsDeviceCompromised(true);
        }
      } catch {
        // ignore if not installed
      }
    })();
  }, []);

  // Auto-lock timer
  useEffect(() => {
    let timer;
    if (isUnlocked) {
      timer = setTimeout(() => {
        lockWallet();
      }, 2 * 60 * 1000); // 2 minutes
    }
    return () => clearTimeout(timer);
  }, [isUnlocked]);

  // Helpers to persist per-wallet counters
  const persistFailedUnlocks = async (walletId, count) => {
    try {
      await setItemAsync(`${WALLET_FAILED_UNLOCKS_PREFIX}${walletId}`, String(count));
    } catch {
      // ignore
    }
    setFailedUnlocksMap((m) => ({ ...m, [walletId]: count }));
  };

  const persistLastFailedAt = async (walletId, ts) => {
    try {
      await setItemAsync(`${WALLET_LAST_FAILED_AT_PREFIX}${walletId}`, String(ts || ""));
    } catch {
      // ignore
    }
    setLastFailedAtMap((m) => ({ ...m, [walletId]: ts }));
  };

  // Hardware key helpers
  const enableBiometricKey = async (label = "wallet_hardware_key") => {
    if (!Keychain) throw new Error("Biometric key support requires react-native-keychain");
    try {
      const existing = await Keychain.getGenericPassword({ service: label });
      if (existing) return true;

      const RNSimpleCrypto = require("react-native-simple-crypto").default;
      let keyBytes = RNSimpleCrypto.utils.randomBytes(32);
      if (keyBytes && typeof keyBytes.then === "function") keyBytes = await keyBytes;
      const keyHex = RNSimpleCrypto.utils.convertArrayBufferToHex(keyBytes);

      const options = {};
      try {
        if (Keychain.ACCESSIBLE) options.accessible = Keychain.ACCESSIBLE.WHEN_UNLOCKED_THIS_DEVICE_ONLY;
        if (Keychain.ACCESS_CONTROL) options.accessControl = Keychain.ACCESS_CONTROL.BIOMETRY_ANY;
        options.service = label;
        options.authenticationPrompt = { title: "Authenticate to use secure wallet key" };
      } catch {
        // ignore unavailable constants
      }

      await Keychain.setGenericPassword("walletKey", keyHex, options);

      // best-effort: zero keyBytes if possible
      if (keyBytes && keyBytes.fill) keyBytes.fill(0);
      return true;
    } catch (err) {
      // eslint-disable-next-line no-console
      console.warn("enableBiometricKey failed");
      return false;
    }
  };

  const getHardwareKey = async (label = "wallet_hardware_key") => {
    if (!Keychain) return null;
    try {
      const creds = await Keychain.getGenericPassword({
        service: label,
        authenticationPrompt: { title: "Authenticate to access wallet key" },
      });
      if (!creds) return null;
      return creds.password;
    } catch {
      // eslint-disable-next-line no-console
      console.warn("getHardwareKey failed");
      return null;
    }
  };

  const removeHardwareKey = async (label = "wallet_hardware_key") => {
    if (!Keychain) return false;
    try {
      await Keychain.resetGenericPassword({ service: label });
      return true;
    } catch {
      return false;
    }
  };

  // ----------- Save Wallet -----------
  // helper to compute AAD from walletId/version
  const makeAadHex = (walletId, version = 1) => {
    const str = `${walletId}|v${version}`;
    // cheapest utf8->hex
    return Array.from(new TextEncoder().encode(str)).map((b) => b.toString(16).padStart(2, "0")).join("");
  };

  const saveWallet = async (privateKey, phrase, password, options = {}) => {
    const useHardwarePreferred = options.useHardwarePreferred ?? true;

    // generate secure random walletId
    let randomId = "";
    try {
      const RNSimpleCrypto = require("react-native-simple-crypto").default;
      let rnd = RNSimpleCrypto.utils.randomBytes(8);
      if (rnd && typeof rnd.then === "function") rnd = await rnd;
      randomId = RNSimpleCrypto.utils.convertArrayBufferToHex(rnd);
    } catch {
      randomId = Math.floor(Math.random() * 1e9).toString(16);
    }
    const walletId = `wallet_${randomId}_${Date.now()}`;

    let encType = "pw";
    let keyHex = null;
    let saltHex = null;

    if (useHardwarePreferred) {
      const hwKey = await getHardwareKey();
      if (hwKey) {
        encType = "hw";
        keyHex = hwKey;
      }
    }

    if (!keyHex) {
      if (!password) throw new Error("Password required to encrypt wallet");
      const derived = await deriveKey(password);
      keyHex = derived.keyHex;
      saltHex = derived.saltHex;
      encType = "pw";
    }

    // compute AAD and perform AES-GCM encryption with AAD bound
    const aadHex = makeAadHex(walletId, 1);
    const { cipherHex: privateKeyCipher, ivHex: privateKeyIv } = await encryptAESGCM(keyHex, privateKey, aadHex);
    const { cipherHex: mnemonicCipher, ivHex: mnemonicIv } = await encryptAESGCM(keyHex, phrase || "", aadHex);

    // zero key reference best-effort
    keyHex = null;

    const encryptedData = {
      version: 1,
      encType,
      privateKeyCipher,
      privateKeyIv,
      mnemonicCipher,
      mnemonicIv,
      aadHex,
      saltHex: saltHex || null,
      createdAt: Date.now(),
    };

    await setItemAsync(`WALLET_ENC_${walletId}`, JSON.stringify(encryptedData));

    // update wallet list
    const wallet = new ethers.Wallet(privateKey);
    const walletListJson = (await getItemAsync("WALLET_LIST")) || "[]";
    let walletList = JSON.parse(walletListJson);
    walletList = walletList.map((w) => ({ ...w, isActive: false }));

    const newWallet = {
      id: walletId,
      name: wallet.address,
      address: wallet.address,
      isActive: true,
    };

    walletList.push(newWallet);
    await setItemAsync("WALLET_LIST", JSON.stringify(walletList));

    setWallets(walletList);
    setCurrentWallet(newWallet);

    return newWallet;
  };

  // ----------- Load Wallets -----------
  const loadWallets = useCallback(async () => {
    setLoading(true);
    try {
      const walletListJson = await getItemAsync("WALLET_LIST");
      const confirmed = await SecureStore.getItemAsync("PHRASE_CONFIRMED");
      setHasBackedUp(confirmed === "true");

      if (walletListJson) {
        const walletList = JSON.parse(walletListJson);
        setWallets(walletList);
        const activeWallet = walletList.find((w) => w.isActive);
        if (activeWallet) setCurrentWallet(activeWallet);
      }
    } finally {
      setLoading(false);
    }
  }, []);

  // ----------- Create New Wallet (encrypted temp) -----------
  const addNewWallet = async (walletName, password, options = {}) => {
    if (!password && !(options.useHardwarePreferred && Keychain)) {
      throw new Error("Password required to create wallet securely unless hardware key is enabled");
    }

    if (isDeviceCompromised) {
      // eslint-disable-next-line no-console
      console.warn("Device appears compromised (root/jailbreak). Creating wallet is not recommended.");
    }

    const newWalletObj = ethers.Wallet.createRandom();

    let keyHex = null;
    let saltHex = null;
    let encType = "pw";

    if (options.useHardwarePreferred) {
      const hwKey = await getHardwareKey();
      if (hwKey) {
        keyHex = hwKey;
        encType = "hw";
      }
    }

    if (!keyHex) {
      const derived = await deriveKey(password);
      keyHex = derived.keyHex;
      saltHex = derived.saltHex;
      encType = "pw";
    }

    // temp wallet id to bind AAD
    const tempId = `temp_${Date.now()}`;
    const aadHex = makeAadHex(tempId, 1);

    const { cipherHex: privateKeyCipher, ivHex: privateKeyIv } = await encryptAESGCM(
      keyHex,
      newWalletObj.privateKey,
      aadHex
    );
    const { cipherHex: mnemonicCipher, ivHex: mnemonicIv } = await encryptAESGCM(
      keyHex,
      newWalletObj.mnemonic?.phrase || "",
      aadHex
    );

    keyHex = null;

    const encrypted = {
      version: 1,
      encType,
      privateKeyCipher,
      privateKeyIv,
      mnemonicCipher,
      mnemonicIv,
      aadHex,
      saltHex: saltHex || null,
      createdAt: Date.now(),
    };

    setTempWalletData({
      walletName,
      address: newWalletObj.address,
      encrypted,
      createdAt: Date.now(),
    });

    setTimeout(() => {
      setTempWalletData((t) => {
        if (!t) return t;
        if (Date.now() - t.createdAt >= 5 * 60 * 1000) return null;
        return t;
      });
    }, 5 * 60 * 1000 + 1000);

    return newWalletObj;
  };

  const importWalletFromPrivateKey = async (privateKey, walletName, password, options = {}) => {
    const newWallet = await saveWallet(privateKey, "", password, options);
    if (walletName) await updateWalletName(newWallet.id, walletName);
    return newWallet;
  };

  const switchWallet = async (walletId) => {
    const updatedWallets = wallets.map((w) => ({ ...w, isActive: w.id === walletId }));
    await setItemAsync("WALLET_LIST", JSON.stringify(updatedWallets));
    setWallets(updatedWallets);
    const activeWallet = updatedWallets.find((w) => w.id === walletId);
    setCurrentWallet(activeWallet || null);
    lockWallet();
  };

  const confirmBackup = async () => {
    await SecureStore.setItemAsync("PHRASE_CONFIRMED", "true");
    setHasBackedUp(true);
  };

  /**
   * unlockWallet(password?)
   * - Uses per-wallet persisted failed unlock counters
   */
  const unlockWallet = async (password) => {
    if (!currentWallet) return false;
    const walletId = currentWallet.id;

    // load persisted counters (in-memory mirrors keep them updated)
    const failed = failedUnlocksMap[walletId] || 0;
    const lastAt = lastFailedAtMap[walletId] || null;

    const MAX_ATTEMPTS = 5;
    if (failed >= MAX_ATTEMPTS) {
      const lockSeconds = Math.min(60 * 10, 2 ** (failed - MAX_ATTEMPTS) * 60);
      const elapsed = lastAt ? Date.now() - lastAt : Infinity;
      if (elapsed < lockSeconds * 1000) {
        const remaining = Math.ceil((lockSeconds * 1000 - elapsed) / 1000);
        throw new Error(`Too many attempts. Please wait ${remaining}s before retrying.`);
      }
    }

    const encDataJson = await getItemAsync(`WALLET_ENC_${walletId}`);
    if (!encDataJson) return false;
    const encData = JSON.parse(encDataJson);

    let keyHex = null;
    try {
      if (encData.encType === "hw") {
        keyHex = await getHardwareKey();
        if (!keyHex) {
          await persistFailedUnlocks(walletId, failed + 1);
          await persistLastFailedAt(walletId, Date.now());
          return false;
        }
      } else {
        if (!password) {
          await persistFailedUnlocks(walletId, failed + 1);
          await persistLastFailedAt(walletId, Date.now());
          return false;
        }
        const derived = await deriveKey(password, encData.saltHex);
        keyHex = derived.keyHex;
      }
    } catch {
      await persistFailedUnlocks(walletId, failed + 1);
      await persistLastFailedAt(walletId, Date.now());
      return false;
    }

    try {
      const privateKey = await decryptAESGCM(keyHex, encData.privateKeyCipher, encData.privateKeyIv, encData.aadHex);
      if (privateKey) {
        setIsUnlocked(true);
        await persistFailedUnlocks(walletId, 0);
        await persistLastFailedAt(walletId, null);

        try {
          await ScreenCapture.preventScreenCaptureAsync();
        } catch {
          // ignore
        }

        // best-effort clear keyHex
        keyHex = null;
        return true;
      }
      // wrong key
      await persistFailedUnlocks(walletId, failed + 1);
      await persistLastFailedAt(walletId, Date.now());
      keyHex = null;
      return false;
    } catch {
      await persistFailedUnlocks(walletId, failed + 1);
      await persistLastFailedAt(walletId, Date.now());
      keyHex = null;
      return false;
    }
  };

  // decrypt-on-demand helper
  const decryptCurrentWalletPrivateKey = async (password) => {
    if (!currentWallet) return null;
    const walletId = currentWallet.id;
    const encDataJson = await getItemAsync(`WALLET_ENC_${walletId}`);
    if (!encDataJson) return null;
    const encData = JSON.parse(encDataJson);

    let keyHex = null;
    if (encData.encType === "hw") {
      keyHex = await getHardwareKey();
      if (!keyHex) return null;
    } else {
      if (!password) throw new Error("Password required to decrypt private key");
      const derived = await deriveKey(password, encData.saltHex);
      keyHex = derived.keyHex;
    }

    try {
      const privateKey = await decryptAESGCM(keyHex, encData.privateKeyCipher, encData.privateKeyIv, encData.aadHex);
      return privateKey;
    } finally {
      keyHex = null;
    }
  };

  const lockWallet = async () => {
    setIsUnlocked(false);
    try {
      await ScreenCapture.allowScreenCaptureAsync();
    } catch {
      // ignore
    }
  };

  const disconnectWallet = async () => {
    for (const wallet of wallets) {
      await deleteItemAsync(`WALLET_ENC_${wallet.id}`);
      await deleteItemAsync(`${WALLET_FAILED_UNLOCKS_PREFIX}${wallet.id}`);
      await deleteItemAsync(`${WALLET_LAST_FAILED_AT_PREFIX}${wallet.id}`);
    }
    await deleteItemAsync("WALLET_LIST");
    await SecureStore.deleteItemAsync("PHRASE_CONFIRMED");
    setWallets([]);
    setCurrentWallet(null);
    setMonBalance("0.0");
    setHasBackedUp(false);
    setIsUnlocked(false);
    setTempWalletData(null);
    setFailedUnlocksMap({});
    setLastFailedAtMap({});

    // Web cleanup: remove only known keys/prefixes
    if (typeof localStorage !== "undefined") {
      try {
        const keysToRemove = [];
        for (let i = 0; i < localStorage.length; i++) {
          const k = localStorage.key(i);
          if (!k) continue;
          if (k.startsWith("WALLET_ENC_") || k.startsWith("FAILED_UNLOCKS_") || k === "WALLET_LIST" || k === "PHRASE_CONFIRMED") keysToRemove.push(k);
        }
        for (const k of keysToRemove) localStorage.removeItem(k);
      } catch {
        // ignore
      }
    }
  };

  const updateWalletName = async (walletId, newName) => {
    const updatedWallets = wallets.map((w) => (w.id === walletId ? { ...w, name: newName } : w));
    await setItemAsync("WALLET_LIST", JSON.stringify(updatedWallets));
    setWallets(updatedWallets);
    if (currentWallet?.id === walletId) setCurrentWallet({ ...currentWallet, name: newName });
  };

  const deleteWallet = async (walletId) => {
    const updatedWallets = wallets.filter((w) => w.id !== walletId);
    await deleteItemAsync(`WALLET_ENC_${walletId}`);
    await deleteItemAsync(`${WALLET_FAILED_UNLOCKS_PREFIX}${walletId}`);
    await deleteItemAsync(`${WALLET_LAST_FAILED_AT_PREFIX}${walletId}`);
    await setItemAsync("WALLET_LIST", JSON.stringify(updatedWallets));
    setWallets(updatedWallets);
    if (currentWallet?.id === walletId) setCurrentWallet(updatedWallets[0] || null);
  };

  const getMonBalance = useCallback(
    async (address) => {
      if (!address || !isUnlocked) {
        setMonBalance("0.0");
        return;
      }
      try {
        const balance = await provider.getBalance(address);
        setMonBalance(ethers.formatEther(balance));
      } catch {
        setMonBalance("0.0");
      }
    },
    [provider, isUnlocked]
  );

  useEffect(() => {
    loadWallets();
  }, [loadWallets]);

  useEffect(() => {
    if (currentWallet?.address && isUnlocked) getMonBalance(currentWallet.address);
    else setMonBalance("0.0");
  }, [currentWallet, getMonBalance, isUnlocked]);

  useEffect(() => {
    const sub = AppState.addEventListener("change", (nextState) => {
      if (appState === "active" && nextState.match(/inactive|background/)) {
        if (isUnlocked) lockWallet();
      }
      setAppState(nextState);
    });
    return () => sub.remove();
  }, [appState, isUnlocked]);

  const validatePasswordStrength = (password) => {
    const reasons = [];
    if (!password || password.length < 10) reasons.push("Password must be at least 10 characters.");
    if (!/[A-Z]/.test(password)) reasons.push("Include an uppercase letter.");
    if (!/[a-z]/.test(password)) reasons.push("Include a lowercase letter.");
    if (!/[0-9]/.test(password)) reasons.push("Include a digit.");
    if (!/[^A-Za-z0-9]/.test(password)) reasons.push("Include a special character.");
    return { valid: reasons.length === 0, reasons };
  };

  const value = {
    wallets,
    currentWallet,
    monBalance,
    loading,
    hasBackedUp,
    isUnlocked,
    addNewWallet,
    importWalletFromPrivateKey,
    switchWallet,
    confirmBackup,
    disconnectWallet,
    getMonBalance,
    unlockWallet,
    lockWallet,
    updateWalletName,
    deleteWallet,
    setTempWalletData,
    tempWalletData,
    saveWallet,
    validatePasswordStrength,
    isDeviceCompromised,
    // Hardware key helpers
    enableBiometricKey,
    getHardwareKey,
    removeHardwareKey,
    decryptCurrentWalletPrivateKey,
  };

  return <WalletContext.Provider value={value}>{children}</WalletContext.Provider>;
};

export const useWallet = () => {
  const context = useContext(WalletContext);
  if (!context) throw new Error("useWallet must be used within WalletProvider");
  return context;
};