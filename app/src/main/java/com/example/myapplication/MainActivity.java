package com.example.myapplication;

import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;

import android.app.AlertDialog;
import android.content.DialogInterface;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Bundle;
import android.os.CancellationSignal;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.util.Base64;
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
    private CancellationSignal cancellationSignal;

    private AlertDialog.Builder builder;
    private AlertDialog dialog;

    private KeyStore keyStore;
    private KeyGenerator keyGenerator;
    private Cipher cipher;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // 初始化控件
        check_btn = findViewById(R.id.check_button);
        auth_btn = findViewById(R.id.authenticate_button);
        // 初始化fingerprintManager实例
        fingerprintManager = getSystemService(FingerprintManager.class);

        // 初始化KeyStore, KeyGenerator, Cipher实例
        initSecureInstance();

        // 生成密钥并存入KeyStore，如果密钥之前已经存在，则直接返回
        initKey();

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
            showDialog("please confirm your fingerprint", null, null);

            FingerprintManager.CryptoObject cryptoObject = new FingerprintManager.CryptoObject(cipher);
            cancellationSignal = new CancellationSignal();
            /**
             * 第一个参数可以是一个crypto对象，或者是null
             * 如果是null，表示只用了本机的指纹校验，但是从理论上来说，设备的指纹扫描结果是可以被拦截和篡改的。所以，对于应用或者应用的服务端来说，并不是绝对安全的。
             * 所以，可以传入一个crypto对象。在扫描成功之后，再加密某些字段传到服务器验证，如果成功，表示这次操作真正的成功了。
             */
            fingerprintManager.authenticate(cryptoObject, cancellationSignal, 0, new FingerprintManager.AuthenticationCallback() {
                @Override
                public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
                    super.onAuthenticationSucceeded(result);

                    try {
                        // 在扫描成功之后，再加密某些字段传到服务器验证，如果成功，表示这次操作真正的成功了。
                        byte[] encrypted = result.getCryptoObject().getCipher().doFinal("test-scret-msg".getBytes());
                        String secretStr = Base64.encodeToString(encrypted, 0);

                        // 省略将 "secretStr" 传到服务器
                        // ...

                        showDialog("onAuthenticationSucceeded", null, null);
                    } catch (BadPaddingException | IllegalBlockSizeException e) {
                        showDialog("fingerprint success but encrypt error, so it is failed", null, null);
                    }
                    // 取消指纹监听
                    cancelFingerprintListenner();
                }

                @Override
                public void onAuthenticationFailed() {
                    super.onAuthenticationFailed();
                    // 指纹验证失败的时候，应该重新触摸指纹去验证，而不能重新调用fingerprintManager.authenticate(...)方法
                    // 也可以调用cancel方法取消指纹操作，此时会进入onAuthenticationError回调。
                    showDialog("onAuthenticationFailed, please try again", null, null);
                }

                @Override
                public void onAuthenticationError(int errorCode, CharSequence errString) {
                    super.onAuthenticationError(errorCode, errString);
                    showDialog("onAuthenticationError", null, null);
                    // 取消指纹监听
                    cancelFingerprintListenner();
                }
            }, null);
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
        if (cancellationSignal != null) {
            cancellationSignal.cancel();
            cancellationSignal = null;
        }
    }
    @Override
    protected void onPause() {
        super.onPause();
        cancelFingerprintListenner();
    }
}
