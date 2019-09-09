package com.example.myapplication;

import android.app.DialogFragment;
import android.content.Context;
import android.content.DialogInterface;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.TextView;

public class FingerprintAuthenticationDialogFragment extends DialogFragment implements FingerprintManagerUtil.DialogFragmentCallback {
    private static final long ERROR_TIMEOUT_MILLIS = 1600;
    private static final long SUCCESS_DELAY_MILLIS = 1300;
    
    private Button cancelBtn;
    private ImageView fingerprintIcon;
    private TextView statuText;

    private MainActivity myActivity;

    Runnable mResetErrorTextRunnable = new Runnable() {
        @Override
        public void run() {
            int hint_color_id = myActivity.getApplicationContext().getResources().getIdentifier("hint_color", "color", myActivity.getPackageName());
            statuText.setTextColor(statuText.getResources().getColor(hint_color_id));

            int fingerprint_hint_id = myActivity.getApplicationContext().getResources().getIdentifier("fingerprint_hint", "string", myActivity.getPackageName());
            statuText.setText(statuText.getResources().getString(fingerprint_hint_id));

            int ic_fp_40px_id = myActivity.getApplicationContext().getResources().getIdentifier("ic_fp_40px", "mipmap", myActivity.getPackageName());
            fingerprintIcon.setImageResource(ic_fp_40px_id);
        }
    };


    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        // Do not create a new Fragment when the Activity is re-created such as orientation changes.
        setRetainInstance(true);
        setStyle(DialogFragment.STYLE_NORMAL, android.R.style.Theme_Material_Light_Dialog);
    }

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
        getDialog().setTitle(getString(R.string.fingerprint_fragment_title));
        View v = inflater.inflate(R.layout.fingerprint_dialog_fragment, container, false);
        cancelBtn = v.findViewById(R.id.cancel_button);
        fingerprintIcon = v.findViewById(R.id.fingerprint_icon);
        statuText = v.findViewById(R.id.fingerprint_status);

        cancelBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                dismiss();
            }
        });

        return v;
    }

    @Override
    public void onAttach(Context context) {
        super.onAttach(context);
        myActivity = (MainActivity)getActivity();
    }

    @Override
    public void onResume() {
        super.onResume();
        FingerprintManagerUtil.startAuthenticate(this);
    }

    @Override
    public void onPause() {
        super.onPause();
        dismiss();
    }

    @Override
    public void onDismiss(DialogInterface dialog) {
        super.onDismiss(dialog);
        FingerprintManagerUtil.cancelFingerprintListenner();
    }

    @Override
    public void onAuthenticated(String successMsg) {
        statuText.removeCallbacks(mResetErrorTextRunnable);
        fingerprintIcon.setImageResource(R.drawable.ic_fingerprint_success);
        statuText.setTextColor(statuText.getResources().getColor(R.color.success_color, null));
        statuText.setText(successMsg);
        fingerprintIcon.postDelayed(new Runnable() {
            @Override
            public void run() {
                dismiss();
                myActivity.afterAuthenticateSuccess();
            }
        }, SUCCESS_DELAY_MILLIS);
    }

    @Override
    public void onFailed(String failedMsg) {
        showError(failedMsg);
    }

    @Override
    public void onError(String errorMsg) {
        if (!FingerprintManagerUtil.selfCancelled) {
            showError(errorMsg);
            fingerprintIcon.postDelayed(new Runnable() {
                @Override
                public void run() {
                    dismiss();
                    myActivity.afterAuthenticateError();
                }
            }, ERROR_TIMEOUT_MILLIS);
        } else {
            myActivity.afterAuthenticateCancel();
        }
    }

    @Override
    public void onHelp(String helpMsg) {
        showError(helpMsg);
    }

    private void showError(CharSequence error) {
        fingerprintIcon.setImageResource(R.drawable.ic_fingerprint_error);
        statuText.setText(error);
        statuText.setTextColor(statuText.getResources().getColor(R.color.warning_color, null));

        statuText.removeCallbacks(mResetErrorTextRunnable);
        statuText.postDelayed(mResetErrorTextRunnable, ERROR_TIMEOUT_MILLIS);
    }
}
