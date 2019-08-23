## FingerprintManager API介绍

### Google Doc：
> https://developer.android.google.cn/reference/kotlin/android/hardware/fingerprint/FingerprintManager

### 公共方法：
设备是否支持指纹识别
> `isHardwareDetected()`

手机是否已经注册了指纹
> `hasEnrolledFingerprints()`

开启指纹扫描
* 参数1： 一个加密对象，可以为null
* 参数2： 一个取消对象，可以用它来取消指纹扫描操作。可以为null
* 参数3： 一个flag, 默认传0
* 参数4： 一个回调对象，里面会实现成功，失败，错误，帮助等回调方法，当指纹扫描完成会进入不同的回调
* 参数5： FingerprintManager将会使用这个handler中的looper来处理来自指纹识别硬件的消息。通常来讲，开发者不用提供这个参数，可以直接置为null
> `authenticate(crypto: FingerprintManager.CryptoObject?, cancel: CancellationSignal?, flags: Int, callback: FingerprintManager.AuthenticationCallback, handler: Handler?)` 

### 子类：
> `FingerprintManager.CryptoObject`
>> `getCipher()`,  `getMac()`,  `getSignature()`

可以传入Signature, Cipher 和 Mac 来生成一个加密对象，这个加密对象可以传入authenticate方法。稍后介绍为什么传它。

> `FingerprintManager.AuthenticationCallback`
>> `onAuthenticationSucceeded(result: FingerprintManager.AuthenticationResult)` // 指纹识别成功

>> `onAuthenticationFailed()` // 指纹识别失败

>> `onAuthenticationError()` // 指纹识别过程中出错，或者用户取消了指纹识别操作

>> `onAuthenticationHelp()` // 指纹识别过程中出错，但错误是可修复的，如指纹扫描器脏了，提示“Sensor dirty, please clean it.”

生成一个回调对象来传入authenticate方法，这个回调对象包含4个回调方法。

> `FingerprintManager.AuthenticationResult`
>> `getCryptoObject()`

指纹识别成功的回调方法里会传入一个AuthenticationResult对象，用这个result对象可以获得指纹扫描时传进来的CryptoObject对象：getCryptoObject

### 相关概念
> KeyStore

安卓中用来存储公钥、私钥或者密钥的一个系统级的东西，有不同类型如：BKS， BouncyCastle， AndroidKeyStore， AndroidCAStore等

> KeyGenerator

用来生成公钥、私钥或者密钥的类，生成的时候提供一个KeyStore类型，生成后可以自动存进对应的KeyStore中

> KeyGenParameterSpec

用来设定一系列的规则来初始化KeyGenerator对象

> Cipher

用来执行加密、解密的一个对象


## 简单实现指纹认证

Google官方提供的api很简单，我们通过这个只需两步即可实现

* Step 1: 检测硬件设备是否支持，以及设备是否已经注册了指纹。(需要权限 `<uses-permission android:name="android.permission.USE_FINGERPRINT" />`)
```java
FingerprintManager fingerprintManager = getSystemService(FingerprintManager.class);

private void checkDeviceFingerprintStatus() {
    boolean isHardwareSupport = fingerprintManager.isHardwareDetected();
    boolean hasEnrolledFingerprints = fingerprintManager.hasEnrolledFingerprints();
}
```

* Step 2: 开启指纹扫描，并传入回调对象
```java
private void fingerprintAuthenticate() {
    fingerprintManager.authenticate(null, null, 0, new FingerprintManager.AuthenticationCallback() {
        @Override
        public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
            super.onAuthenticationSucceeded(result);
            Log.d("DEBUG","onAuthenticationSucceeded"); // 用正确的指头触摸，会成功，并输出这个日志
        }

        @Override
        public void onAuthenticationFailed() {
            super.onAuthenticationFailed();
            Log.d("DEBUG","onAuthenticationFailed"); // 用错误的指头触摸，会失败，并输出这个日志
        }
    }, null);
}
```
上面这样就已经实现指纹认证了，是不是很简单。你如果有做demo，发现现在已经可以看到日志输出了。

但是你发现没有弹出框告诉用户按指纹，很不友好，接下来我们加上弹窗提示。

## 添加用户提示信息
先封装一个弹窗方法，用AlertDialog。当然更好的可以用DialogFragment，那样可以定制UI。
```java
private AlertDialog.Builder builder;
private AlertDialog dialog;

private void showDialog(String str, 
    @Nullable DialogInterface.OnClickListener positiveBtnListener, 
    @Nullable DialogInterface.OnClickListener negativeBtnListener) {
    if (dialog!= null && dialog.isShowing()) {
        dialog.dismiss();
    }
    builder = new AlertDialog.Builder(this);
    builder.setMessage(str).setTitle("title");

    if (positiveBtnListener != null) {
        builder.setPositiveButton("Yes", positiveBtnListener);
    }
    if (negativeBtnListener != null) {
        builder.setNegativeButton("No", negativeBtnListener);
    }
    dialog = builder.create();
    dialog.show();
}
```

然后在指纹扫描之前，提示用户开始扫描了，请触摸指纹
```java
private void fingerprintAuthenticate() {
    showDialog("please confirm your fingerprint", null, null);
    fingerprintManager.authenticate(null, null, 0, new FingerprintManager.AuthenticationCallback() {
        @Override
        public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
            super.onAuthenticationSucceeded(result);
            showDialog("onAuthenticationSucceeded", null, null);
        }

        @Override
        public void onAuthenticationFailed() {
            super.onAuthenticationFailed();
            showDialog("onAuthenticationFailed, please try again", null, null);
        }
    }, null);
}
```

## 取消指纹监听
上面基本上完成了指纹识别的应用，但是是及其简单的，不能适用于生产。

首先一点就是，如果我们没有验证指纹，这个进程就一直在运行状态，指纹识别传感器就会一直被占用。如果其他应用使用指纹传感器，就会失败。

所以我们要在不用的时候，将指纹识别取消掉。通过上面提到的CancellationSignal类
```java
private CancellationSignal cancellationSignal;

private void fingerprintAuthenticate() {
    showDialog("please confirm your fingerprint", null, null);

    cancellationSignal = new CancellationSignal();
    fingerprintManager.authenticate(null, cancellationSignal, 0, new FingerprintManager.AuthenticationCallback() {
        @Override
        public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
            super.onAuthenticationSucceeded(result);
            showDialog("onAuthenticationSucceeded", null, null);
            // 取消指纹监听
            cancelFingerprintListenner();
        }

        @Override
        public void onAuthenticationFailed() {
            super.onAuthenticationFailed();
            showDialog("onAuthenticationFailed, please try again", null, null);
            // 指纹验证失败的时候，应该重新触摸指纹去验证，而不能重新调用fingerprintManager.authenticate(...)方法
            // 也可以调用cancel方法取消指纹操作，此时会进入onAuthenticationError回调。
            // cancelFingerprintListenner();
        }

        @Override
        public void onAuthenticationError(int errorCode, CharSequence errString) {
            super.onAuthenticationError(errorCode, errString);
            showDialog("onAuthenticationError", null, null);
            // 取消指纹监听
            cancelFingerprintListenner();
        }
    }, null);
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
```

## 用户注册了新的指纹怎么办？
上面我们已经实现了验证本地的指纹，而且如果你添加了新的指纹，也可以通过验证。

但是从业务角度来说，如果设备注册了新的指纹，在我们的app中，应该提示用户，并重新验证。

这个怎么实现呢？这个就需要用到我们之前提到的KeyStore、密钥、加密相关的内容了。

```java
private KeyStore keyStore;
private KeyGenerator keyGenerator;
private Cipher cipher;

...
initSecureInstance();
initKey();
...

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
            * 上述情况下，key都会失效，cipher.init都会抛出异常 KeyPermanentlyInvalidatedException。我们以此判断用户是否需要重新验证。
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
```

接下来我们在调用指纹扫描的时候，先判断key是否失效，如果失效，用户需要重新验证。
```java
private void fingerprintAuthenticate() {
    // 我们每次使用 crypto 对象之前都需要init cipher， 因为cipher对象只能doFinal一次。
    if (initCipher()) {
        showDialog("please confirm your fingerprint", null, null);

        cancellationSignal = new CancellationSignal();
        fingerprintManager.authenticate(null, cancellationSignal, 0, new FingerprintManager.AuthenticationCallback() {
            @Override
            public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
                super.onAuthenticationSucceeded(result);
                showDialog("onAuthenticationSucceeded", null, null);
                // 取消指纹监听
                cancelFingerprintListenner();
            }

            @Override
            public void onAuthenticationFailed() {
                super.onAuthenticationFailed();
                showDialog("onAuthenticationFailed, please try again", null, null);
                // 指纹验证失败的时候，应该重新触摸指纹去验证，而不能重新调用fingerprintManager.authenticate(...)方法
                // 也可以调用cancel方法取消指纹操作，此时会进入onAuthenticationError回调。
                // cancelFingerprintListenner();
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
                    // 删除key
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
```
这样我们就实现了监测用户是否添加了新的指纹，并做相应的操作。当然，真实场景是需要用户重新输入密码来重新生成key的。这样才可以保证不是陌生人添加的指纹。

目前我们基本实现了本地指纹的验证，也保证了一定的安全性。但是对于一些高风险的操作，比如支付，仅仅凭指纹验证成功，服务器端是不可以相信是真的成功的。

因为从理论上说，设备的指纹扫描结果是可以被拦截和篡改的。所以，对于应用或者应用的服务端来说，并不是绝对安全的。

那怎么保证绝对的安全呢？就需要我们在指纹验证成功之后，再跟服务器端做一次校验。

## 指纹扫描成功之后再次加密验证

上面提到的，authenticate的时候，传入的一个crypto对象，就派上用场了。

这个对象可以在指纹验证成功的回调中获得：`result.getCryptoObject()`

```java
try {
    // 在扫描成功之后，再加密某些字段传到服务器验证，如果成功，表示这次操作真正的成功了。
    byte[] encrypted = result.getCryptoObject().getCipher().doFinal("testmsg".getBytes());
    String secretStr = Base64.encodeToString(encrypted, 0);

    // 省略将 "secretStr" 传到服务器

    showDialog("onAuthenticationSucceeded", null, null);
} catch (BadPaddingException | IllegalBlockSizeException e) {
    showDialog("fingerprint success but encrypt error, so it is failed", null, null);
}
```

## 代码
本demo的所有代码可以在我的github中找到：https://github.com/LiShuxue/Fingerprint-Demo/tree/fingerprint