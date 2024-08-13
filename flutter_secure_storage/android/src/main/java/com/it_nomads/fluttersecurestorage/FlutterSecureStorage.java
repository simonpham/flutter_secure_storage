package com.it_nomads.fluttersecurestorage;

import android.content.Context;
import android.content.SharedPreferences;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;

import com.it_nomads.fluttersecurestorage.crypto.EncryptedSharedPreferences;
import com.it_nomads.fluttersecurestorage.crypto.MasterKey;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.HashMap;
import java.util.Map;

public class FlutterSecureStorage {

    private final Context applicationContext;
    protected String ELEMENT_PREFERENCES_KEY_PREFIX = "VGhpcyBpcyB0aGUgcHJlZml4IGZvciBhIHNlY3VyZSBzdG9yYWdlCg";
    protected Map<String, Object> options;
    private String SHARED_PREFERENCES_NAME = "FlutterSecureStorage";
    private SharedPreferences preferences;

    public FlutterSecureStorage(Context context, Map<String, Object> options) {
        this.options = options;
        applicationContext = context.getApplicationContext();
    }

    @SuppressWarnings({"ConstantConditions"})
    boolean getResetOnError() {
        return options.containsKey("resetOnError") && options.get("resetOnError").equals("true");
    }

    public boolean containsKey(String key) {
        ensureInitialized();
        return preferences.contains(key);
    }

    public String addPrefixToKey(String key) {
        return ELEMENT_PREFERENCES_KEY_PREFIX + "_" + key;
    }

    public String read(String key) throws Exception {
        ensureInitialized();

        return preferences.getString(key, null);
    }

    @SuppressWarnings("unchecked")
    public Map<String, String> readAll() throws Exception {
        ensureInitialized();

        Map<String, String> raw = (Map<String, String>) preferences.getAll();

        Map<String, String> all = new HashMap<>();
        for (Map.Entry<String, String> entry : raw.entrySet()) {
            String keyWithPrefix = entry.getKey();
            if (keyWithPrefix.contains(ELEMENT_PREFERENCES_KEY_PREFIX)) {
                String key = entry.getKey().replaceFirst(ELEMENT_PREFERENCES_KEY_PREFIX + '_', "");
                all.put(key, entry.getValue());
            }
        }
        return all;
    }

    public void write(String key, String value) throws Exception {
        ensureInitialized();

        SharedPreferences.Editor editor = preferences.edit();

        editor.putString(key, value);
        editor.apply();
    }

    public void delete(String key) {
        ensureInitialized();

        SharedPreferences.Editor editor = preferences.edit();
        editor.remove(key);
        editor.apply();
    }

    public void deleteAll() {
        ensureInitialized();

        final SharedPreferences.Editor editor = preferences.edit();
        editor.clear();
        editor.apply();
    }

   /** @noinspection DataFlowIssue*/
   protected void ensureOptions(){
       if (options.containsKey("sharedPreferencesName") && !((String) options.get("sharedPreferencesName")).isEmpty()) {
           SHARED_PREFERENCES_NAME = (String) options.get("sharedPreferencesName");
       }

       if (options.containsKey("preferencesKeyPrefix") && !((String) options.get("preferencesKeyPrefix")).isEmpty()) {
           ELEMENT_PREFERENCES_KEY_PREFIX = (String) options.get("preferencesKeyPrefix");
       }
    }

    private void ensureInitialized() {
        // Check if already initialized.
        ensureOptions();
        try {
            preferences = initializeEncryptedSharedPreferencesManager(applicationContext);
        } catch (Exception e) {
            Log.e("SecureStorageAndroid", "EncryptedSharedPreferences initialization failed", e);
        }
    }

    private SharedPreferences initializeEncryptedSharedPreferencesManager(Context context) throws GeneralSecurityException, IOException {
        MasterKey key = new MasterKey.Builder(context)
                .setKeyGenParameterSpec(
                        new KeyGenParameterSpec
                                .Builder(MasterKey.DEFAULT_MASTER_KEY_ALIAS, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                                .setKeySize(256).build())
                .build();
        return EncryptedSharedPreferences.create(
                context,
                SHARED_PREFERENCES_NAME,
                key,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        );
    }
}
