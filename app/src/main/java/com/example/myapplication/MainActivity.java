package com.example.myapplication;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;
import androidx.biometric.BiometricPrompt;

import android.app.AlertDialog;
import android.content.DialogInterface;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.Button;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class MainActivity extends AppCompatActivity {
    private Button check_btn;
    private Button auth_btn;

    private FingerprintManager fingerprintManager;
    private boolean isHardwareSupport = false;
    private boolean hasEnrolledFingerprints = false;

    private AlertDialog.Builder builder;
    private AlertDialog dialog;

    private KeyStore keyStore;
    private KeyGenerator keyGenerator;
    private Cipher cipher;

    private BiometricPrompt biometricPrompt;
    private BiometricPrompt.CryptoObject cryptoObject;
    private BiometricPrompt.PromptInfo promptInfo;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // 初始化控件
        check_btn = findViewById(R.id.check_button);
        auth_btn = findViewById(R.id.authenticate_button);

        // 初始化KeyStore, KeyGenerator, Cipher实例
        initSecureInstance();

        // 生成密钥并存入KeyStore，如果密钥之前已经存在，则直接返回
        initKey();

        // 初始化指纹相关
        initBiometric();

        check_btn.setOnClickListener(new View.OnClickListener(){
            @Override
            public void onClick(View view) {
                checkDeviceFingerprintStatus();
            }
        });

        auth_btn.setOnClickListener(new View.OnClickListener(){
            @Override
            public void onClick(View view) {
                fingerprintAuthenticate();
            }
        });
    }

    private void initBiometric() {
        // 初始化fingerprintManager实例
        fingerprintManager = getSystemService(FingerprintManager.class);

        // 初始化biometricPrompt
        Executor newExecutor = Executors.newSingleThreadExecutor();
        biometricPrompt = new BiometricPrompt(this, newExecutor, new BiometricPrompt.AuthenticationCallback() {
            @Override
            public void onAuthenticationSucceeded(@NonNull BiometricPrompt.AuthenticationResult result) {
                super.onAuthenticationSucceeded(result);
                try {
                    // 在扫描成功之后，再加密某些字段传到服务器验证，如果成功，表示这次操作真正的成功了。
                    byte[] encrypted = result.getCryptoObject().getCipher().doFinal("test-scret-msg".getBytes());
                    String secretStr = Base64.encodeToString(encrypted, 0);

                    // 省略将 "secretStr" 传到服务器
                    // ...
                    Log.d("DEBUG","onAuthenticationSucceeded");
                } catch (BadPaddingException | IllegalBlockSizeException e) {
                    Log.d("DEBUG","fingerprint success but encrypt error, so it is failed");
                }
                // 取消指纹监听
                cancelFingerprintListenner();
            }

            @Override
            public void onAuthenticationFailed() {
                super.onAuthenticationFailed();
                Log.d("DEBUG","onAuthenticationFailed, please try again");
            }

            @Override
            public void onAuthenticationError(int errorCode, CharSequence errString) {
                super.onAuthenticationError(errorCode, errString);
                Log.d("DEBUG","onAuthenticationError");
                // 取消指纹监听
                cancelFingerprintListenner();
            }
        });

        cryptoObject = new BiometricPrompt.CryptoObject(cipher);
        promptInfo = new BiometricPrompt.PromptInfo.Builder()
                .setTitle("Title")
                .setSubtitle("Subtitle")
                .setDescription("This is the description")
                .setNegativeButtonText("Cancel")
                .build();
    }

    private void initSecureInstance() {
        try {
            // 初始化keystore对象（keystore提供商）
            keyStore = KeyStore.getInstance("AndroidKeyStore");
        } catch (KeyStoreException e) {
            throw new RuntimeException("Failed to get an instance of KeyStore", e);
        }

        try {
            // 初始化密钥生成器（算法，keystore提供商）
            keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new RuntimeException("Failed to get an instance of KeyGenerator", e);
        }

        try {
            // 构建加密/解密类对象 （算法/加密模式/填充方式）
            cipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/" + KeyProperties.BLOCK_MODE_CBC + "/" + KeyProperties.ENCRYPTION_PADDING_PKCS7);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new RuntimeException("Failed to get an instance of Cipher", e);
        }
    }

    private void initKey() {
        try {
            // 尝试从keyStore中获取密钥，如果存在就不会重新生成密钥。
            // 因为如果每次运行都重新生成密钥，就没有办法保证如果添加了新的指纹，让密钥失效了。所以只能第一次使用的时候生成密钥，以后一直用这个，如果以后检测到失效之后，重新生成。
            keyStore.load(null);
            SecretKey key = (SecretKey) keyStore.getKey("mySecretKey", null);
            if (key != null) {
                return;
            }

            // 通过KeyKeyGenParameterSpec.Builder构建密钥，名字是”mySecretKey“， 密钥可用于加密解密
            KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder("mySecretKey", KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC) // 加密模式
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7) // 填充方式
                    /**
                     * 默认是false, 无论用户是否已通过身份验证，都可以使用密钥。
                     * 设置为true表示
                     *      1. 只有在设置安全锁定屏幕时才能生成密钥
                     *      2. 用户只有通过身份验证才可使用，身份验证是指通过设备图案锁，密码锁或指纹锁等。
                     *      3. 禁用或重置屏幕锁，添加指纹或者删除所有指纹，密钥自动失效。
                     */
                    .setUserAuthenticationRequired(true)
                    /**
                     * 设置是否应在注册生物识别时使此密钥无效。
                     * 默认是true, 添加指纹或者删除所有指纹，密钥自动失效。
                     * 设置为false, 添加指纹或者删除所有指纹则不会失效
                     */
                    .setInvalidatedByBiometricEnrollment(true); // 此行可以省略

            keyGenerator.init(builder.build());
            keyGenerator.generateKey(); // 生成密钥，密钥会存在KeyStore中
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | CertificateException| UnrecoverableKeyException | KeyStoreException | IOException e) {
            throw new RuntimeException(e);
        }
    }

    // 初始化cipher对象，返回值表示初始化成功或者失败，取决于设备的屏幕锁或指纹是否变化。
    private boolean initCipher() {
        try {
            keyStore.load(null);
            SecretKey key = (SecretKey) keyStore.getKey("mySecretKey", null);
            /**
             * 1. 用户添加了新的指纹
             * 2. 用户删除了所有的指纹
             * 3. 用户关闭了屏幕锁
             * 4. 用户改变了屏幕锁的方式
             *
             * 上述情况下，key都会失效，cipher.init都会抛出异常 KeyPermanentlyInvalidatedException。
             */
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return true;
        } catch (KeyPermanentlyInvalidatedException e) {
            // 出现了上述情况
            return false;
        } catch (KeyStoreException | CertificateException | UnrecoverableKeyException | IOException | NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException("Failed to init Cipher", e);
        }
    }

    private void checkDeviceFingerprintStatus() {
        // 需要权限 <uses-permission android:name="android.permission.USE_FINGERPRINT" />
        isHardwareSupport = fingerprintManager.isHardwareDetected();
        hasEnrolledFingerprints = fingerprintManager.hasEnrolledFingerprints();
        showDialog("isHardwareSupport: " + isHardwareSupport + " && " + "hasEnrolledFingerprints: " + hasEnrolledFingerprints, null, null);
    }

    private void fingerprintAuthenticate() {
        // 我们每次使用 crypto 对象之前都需要init cipher， 因为cipher对象只能doFinal一次。
        if (initCipher()) {
            /**
             * 第一个参数是系统提供的弹出框
             *
             * 第二个参数可以是一个crypto对象，或者是null
             * 如果是null，表示只用了本机的指纹校验，但是从理论上来说，设备的指纹扫描结果是可以被拦截和篡改的。所以，对于应用或者应用的服务端来说，并不是绝对安全的。
             * 所以，可以传入一个crypto对象。在扫描成功之后，再加密某些字段传到服务器验证，如果成功，表示这次操作真正的成功了。
             */
            biometricPrompt.authenticate(promptInfo, cryptoObject);
        } else {
            String msg = "You have enrolled the new fingerprint or changed the device setting about screen lock, the key is invalidate now. Do you want re-generate the key ?";
            showDialog(msg, new DialogInterface.OnClickListener() {
                @Override
                public void onClick(DialogInterface dialog, int which) {
                    try {
                        keyStore.deleteEntry("mySecretKey");
                        initKey();
                    } catch (KeyStoreException e) {
                        e.printStackTrace();
                    }
                }
            }, new DialogInterface.OnClickListener() {
                @Override
                public void onClick(DialogInterface dialog, int which) {
                    dialog.dismiss();
                }
            });

        }
    }

    private void showDialog(String str, @Nullable DialogInterface.OnClickListener positiveBtnListener, @Nullable DialogInterface.OnClickListener negativeBtnListener) {
        if (dialog!= null && dialog.isShowing()) {
            dialog.dismiss();
        }
        builder = new AlertDialog.Builder(this);
        builder.setMessage(str)
                .setTitle("title");
        if (positiveBtnListener != null) {
            builder.setPositiveButton("Yes", positiveBtnListener);
        }
        if (negativeBtnListener != null) {
            builder.setNegativeButton("No", negativeBtnListener);
        }

        dialog = builder.create();
        dialog.show();
    }

    private void cancelFingerprintListenner() {
        biometricPrompt.cancelAuthentication();
    }
    @Override
    protected void onPause() {
        super.onPause();
        cancelFingerprintListenner();
    }
}
