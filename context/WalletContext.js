/**
 * src/context/WalletContext.js
 *
 * Hardened WalletContext:
 * - secure RNG validated for private key generation
 * - addNewWallet does NOT return plaintext; uses temp encrypted blob
 * - revealTempWalletMnemonic / confirmSaveTempWallet / discardTempWallet APIs
 * - signMessage / signTransaction helpers to avoid returning private key
 * - failed-unlock counters persisted; key buffers zeroed
 *
 * NOTE: Verify react-native-simple-crypto, react-native-keychain and expo-secure-store APIs in your env.
 */

import React, { createContext, useState, useEffect, useContext, useCallback, useMemo } from "react";
import { ethers } from "ethers";
import { setItemAsync, getItemAsync, deleteItemAsync } from "../utils/secureStore";
import { AppState } from "react-native";
import {
  deriveKey,
  encryptAESGCM,
  decryptAESGCM,
  hexToUint8,
  zeroBuffer,
  uint8ToHex,
} from "../utils/cryptoHelpers";
import * as ScreenCapture from "expo-screen-capture";

let Keychain = null;
try {
  // eslint-disable-next-line global-require
  Keychain = require("react-native-keychain");
} catch {
  Keychain = null;
}

const WALLET_FAILED_UNLOCKS_PREFIX = "FAILED_UNLOCKS_";
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
  const [tempWalletData, setTempWalletData] = useState(null);
  const [failedUnlocksMap, setFailedUnlocksMap] = useState({});
  const [lastFailedAtMap, setLastFailedAtMap] = useState({});
  const RPC_URL = "https://testnet-rpc.monad.xyz";
  const provider = useMemo(() => new ethers.JsonRpcProvider(RPC_URL), []);
  const [isDeviceCompromised, setIsDeviceCompromised] = useState(false);

  // load wallet list and counters
  useEffect(() => {
    (async () => {
      try {
        const wlJson = await getItemAsync("WALLET_LIST");
        const list = wlJson ? JSON.parse(wlJson) : [];
        const failedMap = {};
        const atMap = {};
        for (const w of list) {
          try {
            const f = await getItemAsync(`${WALLET_FAILED_UNLOCKS_PREFIX}${w.id}`);
            const at = await getItemAsync(`${WALLET_LAST_FAILED_AT_PREFIX}${w.id}`);
            failedMap[w.id] = f ? parseInt(f, 10) : 0;
            atMap[w.id] = at ? parseInt(at, 10) : null;
          } catch {
            failedMap[w.id] = 0;
            atMap[w.id] = null;
          }
        }
        setFailedUnlocksMap(failedMap);
        setLastFailedAtMap(atMap);
        if (list.length) {
          setWallets(list);
          const activeWallet = list.find((w) => w.isActive);
          if (activeWallet) setCurrentWallet(activeWallet);
        }
      } catch {
        // minimal logging to avoid leaking details
        // eslint-disable-next-line no-console
        console.error("init: failed to load wallet metadata");
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  useEffect(() => {
    (async () => {
      try {
        // eslint-disable-next-line global-require
        const JailMonkey = require("jail-monkey");
        if (JailMonkey && (JailMonkey.isJailBroken() || JailMonkey.isOnSimulator())) {
          setIsDeviceCompromised(true);
        }
      } catch {
        // ignore
      }
    })();
  }, []);

  useEffect(() => {
    let timer;
    if (isUnlocked) {
      timer = setTimeout(() => lockWallet(), 2 * 60 * 1000);
    }
    return () => clearTimeout(timer);
  }, [isUnlocked]);

  const persistFailedUnlocks = async (walletId, count) => {
    try {
      await setItemAsync(`${WALLET_FAILED_UNLOCKS_PREFIX}${walletId}`, String(count));
      setFailedUnlocksMap((m) => ({ ...m, [walletId]: count }));
    } catch {
      // do not crash UI
    }
  };

  const persistLastFailedAt = async (walletId, ts) => {
    try {
      await setItemAsync(`${WALLET_LAST_FAILED_AT_PREFIX}${walletId}`, ts ? String(ts) : "");
      setLastFailedAtMap((m) => ({ ...m, [walletId]: ts }));
    } catch {
      // ignore
    }
  };

  const enableBiometricKey = async (label = "wallet_hardware_key") => {
    if (!Keychain) throw new Error("Biometric key support requires react-native-keychain");
    try {
      const existing = await Keychain.getGenericPassword({ service: label });
      if (existing) return true;

      const RNSimpleCrypto = require("react-native-simple-crypto").default;
      let keyBytes = RNSimpleCrypto.utils.randomBytes(32);
      if (keyBytes && typeof keyBytes.then === "function") keyBytes = await keyBytes;
      const keyHex = RNSimpleCrypto.utils.convertArrayBufferToHex(keyBytes);

      const options = { service: label, authenticationPrompt: { title: "Authenticate to use secure wallet key" } };
      try {
        if (Keychain.ACCESSIBLE) options.accessible = Keychain.ACCESSIBLE.WHEN_UNLOCKED_THIS_DEVICE_ONLY;
        if (Keychain.ACCESS_CONTROL) options.accessControl = Keychain.ACCESS_CONTROL.BIOMETRY_ANY;
      } catch {
        // ignore if constants not present
      }

      await Keychain.setGenericPassword("walletKey", keyHex, options);

      if (keyBytes && keyBytes.fill) keyBytes.fill(0);
      return true;
    } catch {
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
      return creds ? creds.password : null;
    } catch {
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

  const makeAadHex = (walletId, version = 1) => {
    const str = `${walletId}|v${version}`;
    const enc = new TextEncoder();
    const bytes = enc.encode(String(str));
    return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
  };

  // generate valid secp256k1 private key (retry loop)
  const generateValidPrivateKey = async () => {
    const RNSimpleCrypto = require("react-native-simple-crypto").default;
    const MAX_ATTEMPTS = 8;
    for (let i = 0; i < MAX_ATTEMPTS; i++) {
      let rnd = RNSimpleCrypto.utils.randomBytes(32);
      if (rnd && typeof rnd.then === "function") rnd = await rnd;
      const pkHex = RNSimpleCrypto.utils.convertArrayBufferToHex(rnd);
      const pk0x = pkHex.startsWith("0x") ? pkHex : `0x${pkHex}`;
      try {
        // ethers will throw for invalid private keys
        const w = new ethers.Wallet(pk0x);
        // success
        return pk0x;
      } catch {
        // try again
      }
    }
    throw new Error("Could not generate valid private key");
  };

  /**
   * saveWallet(privateKey, phrase, password, options)
   * - persists encrypted wallet and updates WALLET_LIST
   * - returns wallet metadata
   */
  const saveWallet = async (privateKey, phrase, password, options = {}) => {
    const useHardwarePreferred = options.useHardwarePreferred ?? true;

    // secure wallet id
    let randomId = "";
    try {
      const RNSimpleCrypto = require("react-native-simple-crypto").default;
      let rnd = RNSimpleCrypto.utils.randomBytes(8);
      if (rnd && typeof rnd.then === "function") rnd = await rnd;
      randomId = RNSimpleCrypto.utils.convertArrayBufferToHex(rnd);
    } catch {
      throw new Error("Secure RNG unavailable");
    }
    const walletId = `wallet_${randomId}_${Date.now()}`;

    let encType = "pw";
    let keyBuf = null;
    let saltHex = null;

    if (useHardwarePreferred) {
      const hwKeyHex = await getHardwareKey();
      if (hwKeyHex) {
        encType = "hw";
        keyBuf = hexToUint8(hwKeyHex);
      }
    }

    if (!keyBuf) {
      if (!password) throw new Error("Password required to encrypt wallet");
      const derived = await deriveKey(password);
      keyBuf = derived.keyBuf;
      saltHex = derived.saltHex;
    }

    const aadHex = makeAadHex(walletId, 1);

    const { cipherHex: privateKeyCipher, ivHex: privateKeyIv } = await encryptAESGCM(keyBuf, privateKey, aadHex);
    const { cipherHex: mnemonicCipher, ivHex: mnemonicIv } = await encryptAESGCM(keyBuf, phrase || "", aadHex);

    if (keyBuf) zeroBuffer(keyBuf);
    keyBuf = null;

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

  /**
   * addNewWallet(walletName, password, options)
   * - creates wallet securely, stores encrypted temp blob, returns only address metadata
   */
  const addNewWallet = async (walletName, password, options = {}) => {
    if (!password && !(options.useHardwarePreferred && Keychain)) {
      throw new Error("Password required to create wallet securely unless hardware key enabled");
    }
    if (isDeviceCompromised) {
      // warn
    }

    const privateKey = await generateValidPrivateKey();
    const wallet = new ethers.Wallet(privateKey);

    // encryption key
    let keyBuf = null;
    let saltHex = null;
    let encType = "pw";

    if (options.useHardwarePreferred) {
      const hwKeyHex = await getHardwareKey();
      if (hwKeyHex) {
        keyBuf = hexToUint8(hwKeyHex);
        encType = "hw";
      }
    }

    if (!keyBuf) {
      const derived = await deriveKey(password);
      keyBuf = derived.keyBuf;
      saltHex = derived.saltHex;
      encType = "pw";
    }

    const tempId = `temp_${Date.now()}`;
    const aadHex = makeAadHex(tempId, 1);

    const { cipherHex: privateKeyCipher, ivHex: privateKeyIv } = await encryptAESGCM(
      keyBuf,
      privateKey,
      aadHex
    );
    const { cipherHex: mnemonicCipher, ivHex: mnemonicIv } = await encryptAESGCM(
      keyBuf,
      wallet.mnemonic?.phrase || "",
      aadHex
    );

    if (keyBuf) zeroBuffer(keyBuf);
    keyBuf = null;

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
      address: wallet.address,
      encrypted,
      createdAt: Date.now(),
    });

    // auto-clear
    setTimeout(() => {
      setTempWalletData((t) => {
        if (!t) return t;
        if (Date.now() - t.createdAt >= 5 * 60 * 1000) return null;
        return t;
      });
    }, 5 * 60 * 1000 + 1000);

    // Do NOT return private key or mnemonic; return address metadata only
    return { address: wallet.address };
  };

  const revealTempWalletMnemonic = async (password) => {
    if (!tempWalletData?.encrypted) return null;
    const enc = tempWalletData.encrypted;
    let keyBuf = null;
    try {
      if (enc.encType === "hw") {
        const hwHex = await getHardwareKey();
        if (!hwHex) return null;
        keyBuf = hexToUint8(hwHex);
      } else {
        if (!password) throw new Error("Password required");
        const derived = await deriveKey(password, enc.saltHex);
        keyBuf = derived.keyBuf;
      }
      const mnemonic = await decryptAESGCM(keyBuf, enc.mnemonicCipher, enc.mnemonicIv, enc.aadHex);
      return mnemonic;
    } catch {
      return null;
    } finally {
      if (keyBuf) zeroBuffer(keyBuf);
      keyBuf = null;
    }
  };

  const confirmSaveTempWallet = async (walletName, password, options = {}) => {
    if (!tempWalletData?.encrypted) throw new Error("No temporary wallet");
    const enc = tempWalletData.encrypted;
    let keyBuf = null;
    try {
      if (enc.encType === "hw") {
        const hwHex = await getHardwareKey();
        if (!hwHex) throw new Error("Hardware key unavailable");
        keyBuf = hexToUint8(hwHex);
      } else {
        if (!password) throw new Error("Password required");
        const derived = await deriveKey(password, enc.saltHex);
        keyBuf = derived.keyBuf;
      }

      const privateKey = await decryptAESGCM(keyBuf, enc.privateKeyCipher, enc.privateKeyIv, enc.aadHex);
      const mnemonic = await decryptAESGCM(keyBuf, enc.mnemonicCipher, enc.mnemonicIv, enc.aadHex);

      const saved = await saveWallet(privateKey, mnemonic, password, options);

      setTempWalletData(null);
      return saved;
    } finally {
      if (keyBuf) zeroBuffer(keyBuf);
      keyBuf = null;
    }
  };

  const discardTempWallet = async () => {
    setTempWalletData(null);
  };

  /**
   * decryptCurrentWalletPrivateKey(password) - deprecated for UI use.
   * Prefer signMessage / signTransaction helpers below.
   */
  const decryptCurrentWalletPrivateKey = async (password) => {
    if (!currentWallet) return null;
    const walletId = currentWallet.id;
    const encDataJson = await getItemAsync(`WALLET_ENC_${walletId}`);
    if (!encDataJson) return null;
    const encData = JSON.parse(encDataJson);

    let keyBuf = null;
    try {
      if (encData.encType === "hw") {
        const hwHex = await getHardwareKey();
        if (!hwHex) return null;
        keyBuf = hexToUint8(hwHex);
      } else {
        if (!password) throw new Error("Password required");
        const derived = await deriveKey(password, encData.saltHex);
        keyBuf = derived.keyBuf;
      }
      const privateKey = await decryptAESGCM(keyBuf, encData.privateKeyCipher, encData.privateKeyIv, encData.aadHex);
      return privateKey;
    } catch {
      return null;
    } finally {
      if (keyBuf) zeroBuffer(keyBuf);
      keyBuf = null;
    }
  };

  /**
   * signMessage(payload, passwordOrPrompt)
   * - decrypts key ephemeral and returns signature; does not return private key
   */
  const signMessage = async (message, password = null) => {
    if (!currentWallet) throw new Error("No active wallet");
    const walletId = currentWallet.id;
    const encDataJson = await getItemAsync(`WALLET_ENC_${walletId}`);
    if (!encDataJson) throw new Error("Encrypted wallet not found");
    const encData = JSON.parse(encDataJson);

    let keyBuf = null;
    try {
      if (encData.encType === "hw") {
        const hwHex = await getHardwareKey();
        if (!hwHex) throw new Error("Hardware key unavailable");
        keyBuf = hexToUint8(hwHex);
      } else {
        if (!password) throw new Error("Password required");
        const derived = await deriveKey(password, encData.saltHex);
        keyBuf = derived.keyBuf;
      }

      const privateKey = await decryptAESGCM(keyBuf, encData.privateKeyCipher, encData.privateKeyIv, encData.aadHex);
      const wallet = new ethers.Wallet(privateKey);
      const signature = await wallet.signMessage(message);

      // zero any sensitive variables
      // can't zero JS string privateKey reliably, but we can null refs
      return signature;
    } finally {
      if (keyBuf) zeroBuffer(keyBuf);
      keyBuf = null;
    }
  };

  /**
   * signTransaction(unsignedTx, password)
   * - unsignedTx is an ethers Transaction request object
   * - returns signed tx (serialized)
   */
  const signTransaction = async (unsignedTx, password = null) => {
    if (!currentWallet) throw new Error("No active wallet");
    const walletId = currentWallet.id;
    const encDataJson = await getItemAsync(`WALLET_ENC_${walletId}`);
    if (!encDataJson) throw new Error("Encrypted wallet not found");
    const encData = JSON.parse(encDataJson);

    let keyBuf = null;
    try {
      if (encData.encType === "hw") {
        const hwHex = await getHardwareKey();
        if (!hwHex) throw new Error("Hardware key unavailable");
        keyBuf = hexToUint8(hwHex);
      } else {
        if (!password) throw new Error("Password required");
        const derived = await deriveKey(password, encData.saltHex);
        keyBuf = derived.keyBuf;
      }

      const privateKey = await decryptAESGCM(keyBuf, encData.privateKeyCipher, encData.privateKeyIv, encData.aadHex);
      const wallet = new ethers.Wallet(privateKey);
      const populated = await wallet.populateTransaction(unsignedTx);
      const signed = await wallet.signTransaction(populated);
      return signed;
    } finally {
      if (keyBuf) zeroBuffer(keyBuf);
      keyBuf = null;
    }
  };

  const unlockWallet = async (password) => {
    if (!currentWallet) return false;
    const walletId = currentWallet.id;
    const failed = failedUnlocksMap[walletId] || 0;
    const lastAt = lastFailedAtMap[walletId] || null;

    const MAX_ATTEMPTS = 5;
    if (failed >= MAX_ATTEMPTS) {
      const lockSeconds = Math.min(60 * 10, 2 ** (failed - MAX_ATTEMPTS) * 60);
      const elapsed = lastAt ? Date.now() - lastAt : Infinity;
      if (elapsed < lockSeconds * 1000) {
        return false;
      }
    }

    const encDataJson = await getItemAsync(`WALLET_ENC_${walletId}`);
    if (!encDataJson) return false;
    const encData = JSON.parse(encDataJson);

    let keyBuf = null;
    try {
      if (encData.encType === "hw") {
        const hwHex = await getHardwareKey();
        if (!hwHex) {
          await persistFailedUnlocks(walletId, failed + 1);
          await persistLastFailedAt(walletId, Date.now());
          return false;
        }
        keyBuf = hexToUint8(hwHex);
      } else {
        if (!password) return false;
        const derived = await deriveKey(password, encData.saltHex);
        keyBuf = derived.keyBuf;
      }
    } catch {
      await persistFailedUnlocks(walletId, failed + 1);
      await persistLastFailedAt(walletId, Date.now());
      return false;
    }

    try {
      await decryptAESGCM(keyBuf, encData.privateKeyCipher, encData.privateKeyIv, encData.aadHex);

      setIsUnlocked(true);
      await persistFailedUnlocks(walletId, 0);
      await persistLastFailedAt(walletId, null);

      try {
        await ScreenCapture.preventScreenCaptureAsync();
      } catch {
        // ignore
      }

      return true;
    } catch {
      await persistFailedUnlocks(walletId, failed + 1);
      await persistLastFailedAt(walletId, Date.now());
      return false;
    } finally {
      if (keyBuf) zeroBuffer(keyBuf);
      keyBuf = null;
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
    try {
      for (const wallet of wallets) {
        await deleteItemAsync(`WALLET_ENC_${wallet.id}`);
        await deleteItemAsync(`${WALLET_FAILED_UNLOCKS_PREFIX}${wallet.id}`);
        await deleteItemAsync(`${WALLET_LAST_FAILED_AT_PREFIX}${wallet.id}`);
      }
      await deleteItemAsync("WALLET_LIST");
      await deleteItemAsync("PHRASE_CONFIRMED");
    } catch {
      // ignore
    }

    setWallets([]);
    setCurrentWallet(null);
    setMonBalance("0.0");
    setHasBackedUp(false);
    setIsUnlocked(false);
    setTempWalletData(null);
    setFailedUnlocksMap({});
    setLastFailedAtMap({});

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
    await setItemAsync("PHRASE_CONFIRMED", "true");
    setHasBackedUp(true);
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
    if (currentWallet?.id === walletId) {
      const newActiveWallet = updatedWallets.find((w) => w.isActive) || updatedWallets[0] || null;
      setCurrentWallet(newActiveWallet);
    }
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
    if (currentWallet?.address && isUnlocked) {
      getMonBalance(currentWallet.address);
    } else {
      setMonBalance("0.0");
    }
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
    revealTempWalletMnemonic,
    confirmSaveTempWallet,
    discardTempWallet,
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
    enableBiometricKey,
    getHardwareKey,
    removeHardwareKey,
    decryptCurrentWalletPrivateKey,
    signMessage,
    signTransaction,
  };

  return <WalletContext.Provider value={value}>{children}</WalletContext.Provider>;
};

export const useWallet = () => {
  const context = useContext(WalletContext);
  if (!context) throw new Error("useWallet must be used within WalletProvider");
  return context;
};
