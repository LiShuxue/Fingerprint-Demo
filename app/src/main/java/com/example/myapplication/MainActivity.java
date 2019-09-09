package com.example.myapplication;

import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;

import android.app.AlertDialog;
import android.content.DialogInterface;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;

import java.security.KeyStoreException;

public class MainActivity extends AppCompatActivity implements FingerprintManagerUtil.ActivityCallback{
    private Button check_btn;
    private Button auth_btn;


    private AlertDialog.Builder builder;
    private AlertDialog dialog;


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // 初始化控件
        check_btn = findViewById(R.id.check_button);
        auth_btn = findViewById(R.id.authenticate_button);

        // 初始化KeyStore, KeyGenerator, Cipher实例
        FingerprintManagerUtil.initSecureInstance(this);

        // 生成密钥并存入KeyStore，如果密钥之前已经存在，则直接返回
        FingerprintManagerUtil.initKey();

        check_btn.setOnClickListener(new View.OnClickListener(){
            @Override
            public void onClick(View view) {
                Boolean canAuthenticate = FingerprintManagerUtil.canAuthenticate();
                showDialog(canAuthenticate.toString(), null, null);
            }
        });

        auth_btn.setOnClickListener(new View.OnClickListener(){
            @Override
            public void onClick(View view) {
                fingerprintAuthenticate();
            }
        });
    }

    private void fingerprintAuthenticate() {
        if (FingerprintManagerUtil.checkDeviceSettingsNotChanged()) {
            FingerprintAuthenticationDialogFragment fragment = new FingerprintAuthenticationDialogFragment();
            fragment.show(getFragmentManager(), "fingerprint_fragment");
        } else {
            String msg = "You have enrolled the new fingerprint or changed the device setting about screen lock, the key is invalidate now. Do you want re-generate the key ?";
            showDialog(msg, new DialogInterface.OnClickListener() {
                @Override
                public void onClick(DialogInterface dialog, int which) {
                    try {
                        FingerprintManagerUtil.keyStore.deleteEntry("mySecretKey");
                        FingerprintManagerUtil.initKey();
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
    @Override
    public void afterAuthenticateSuccess() {
        showDialog("afterAuthenticateSuccess", null, null);
    }
    @Override
    public void afterAuthenticateError() {
        showDialog("afterAuthenticateError", null, null);
    }
    @Override
    public void afterAuthenticateCancel() {
        showDialog("afterAuthenticateCancel", null, null);
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
}
