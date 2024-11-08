package com.it_nomads.fluttersecurestorage.ciphers;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;

import java.util.Map;

enum KeyCipherAlgorithm {
    RSA_ECB_PKCS1Padding(1),
    RSA_ECB_OAEPwithSHA_256andMGF1Padding(Build.VERSION_CODES.M);
    final int minVersionCode;

    KeyCipherAlgorithm(int minVersionCode) {
        this.minVersionCode = minVersionCode;
    }

    public KeyCipher keyCipher(Context context) throws Exception {
        if (this != KeyCipherAlgorithm.RSA_ECB_OAEPwithSHA_256andMGF1Padding) {
            throw new IllegalStateException("Unsupported key cipher algorithm: " + this);
        }

        return new RSACipherOAEPImplementation(context);
    }
}

enum StorageCipherAlgorithm {
    AES_CBC_PKCS7Padding(1),
    AES_GCM_NoPadding(Build.VERSION_CODES.M);
    final int minVersionCode;

    StorageCipherAlgorithm(int minVersionCode) {
        this.minVersionCode = minVersionCode;
    }

    public StorageCipher storageCipher(Context context, KeyCipher keyCipher) throws Exception {
        if (this != StorageCipherAlgorithm.AES_GCM_NoPadding) {
            throw new IllegalStateException("Unsupported storage cipher algorithm: " + this);
        }

        return new StorageCipherGCMImplementation(context, keyCipher);
    }
}

public class StorageCipherFactory {
    private static final String ELEMENT_PREFERENCES_ALGORITHM_PREFIX = "FlutterSecureSAlgorithm";
    private static final String ELEMENT_PREFERENCES_ALGORITHM_KEY = ELEMENT_PREFERENCES_ALGORITHM_PREFIX + "Key";
    private static final String ELEMENT_PREFERENCES_ALGORITHM_STORAGE = ELEMENT_PREFERENCES_ALGORITHM_PREFIX + "Storage";
    private static final KeyCipherAlgorithm DEFAULT_KEY_ALGORITHM = KeyCipherAlgorithm.RSA_ECB_OAEPwithSHA_256andMGF1Padding;
    private static final StorageCipherAlgorithm DEFAULT_STORAGE_ALGORITHM = StorageCipherAlgorithm.AES_GCM_NoPadding;

    private final KeyCipherAlgorithm savedKeyAlgorithm;
    private final StorageCipherAlgorithm savedStorageAlgorithm;
    private final KeyCipherAlgorithm currentKeyAlgorithm;
    private final StorageCipherAlgorithm currentStorageAlgorithm;

    public StorageCipherFactory(SharedPreferences source, Map<String, Object> options) {
        savedKeyAlgorithm = KeyCipherAlgorithm.valueOf(source.getString(ELEMENT_PREFERENCES_ALGORITHM_KEY, DEFAULT_KEY_ALGORITHM.name()));
        savedStorageAlgorithm = StorageCipherAlgorithm.valueOf(source.getString(ELEMENT_PREFERENCES_ALGORITHM_STORAGE, DEFAULT_STORAGE_ALGORITHM.name()));

        final KeyCipherAlgorithm currentKeyAlgorithmTmp = KeyCipherAlgorithm.valueOf(getFromOptionsWithDefault(options, "keyCipherAlgorithm", DEFAULT_KEY_ALGORITHM.name()));
        currentKeyAlgorithm = (currentKeyAlgorithmTmp.minVersionCode <= Build.VERSION.SDK_INT) ? currentKeyAlgorithmTmp : DEFAULT_KEY_ALGORITHM;
        final StorageCipherAlgorithm currentStorageAlgorithmTmp = StorageCipherAlgorithm.valueOf(getFromOptionsWithDefault(options, "storageCipherAlgorithm", DEFAULT_STORAGE_ALGORITHM.name()));
        currentStorageAlgorithm = (currentStorageAlgorithmTmp.minVersionCode <= Build.VERSION.SDK_INT) ? currentStorageAlgorithmTmp : DEFAULT_STORAGE_ALGORITHM;
    }

    private String getFromOptionsWithDefault(Map<String, Object> options, String key, String defaultValue) {
        final Object value = options.get(key);
        return value != null ? value.toString() : defaultValue;
    }

    public boolean requiresReEncryption() {
        return savedKeyAlgorithm != currentKeyAlgorithm || savedStorageAlgorithm != currentStorageAlgorithm;
    }

    public StorageCipher getSavedStorageCipher(Context context) throws Exception {
        final KeyCipher keyCipher = savedKeyAlgorithm.keyCipher(context);
        return savedStorageAlgorithm.storageCipher(context, keyCipher);
    }

    public StorageCipher getCurrentStorageCipher(Context context) throws Exception {
        final KeyCipher keyCipher = currentKeyAlgorithm.keyCipher(context);
        return currentStorageAlgorithm.storageCipher(context, keyCipher);
    }

    public void storeCurrentAlgorithms(SharedPreferences.Editor editor) {
        editor.putString(ELEMENT_PREFERENCES_ALGORITHM_KEY, currentKeyAlgorithm.name());
        editor.putString(ELEMENT_PREFERENCES_ALGORITHM_STORAGE, currentStorageAlgorithm.name());
    }

    public void removeCurrentAlgorithms(SharedPreferences.Editor editor) {
        editor.remove(ELEMENT_PREFERENCES_ALGORITHM_KEY);
        editor.remove(ELEMENT_PREFERENCES_ALGORITHM_STORAGE);
    }
}
