package aarkay.a2048game;

import android.util.Log;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

public class Locker {
    // Encryption method
    public static void encrypt(String key, File inFile, File outFile) throws Exception {
        lock(Cipher.ENCRYPT_MODE, key, inFile, outFile);
    }

    // Decryption method
    public static void decrypt(String key, File inFile, File outFile) throws Exception {
        Log.d("Inside decrypt key:", key);
        lock(Cipher.DECRYPT_MODE, key, inFile, outFile);
    }

    // Lock method will take in file and encrypt/decrypt based on cipherMode
    private static void lock(int cipherMode, String key, File inFile, File outFile) throws Exception {
        try {
            Log.d("Inside Lock", key);
            Key skey = new SecretKeySpec(key.getBytes(), "AES"); // Create secretkey
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(cipherMode, skey);

            // File input stream
            FileInputStream inStream = new FileInputStream(inFile);
            byte[] inBytes = new byte[(int) inFile.length()]; // Create a Byte array with length of file
            inStream.read(inBytes); // Parse byte array into input stream

            byte[] outBytes = cipher.doFinal(inBytes); // Apply the cipher(en/decrypt) the byte array

            // File output stream
            FileOutputStream outStream = new FileOutputStream(outFile);
            outStream.write(outBytes); // Parse the byte array into output stream

            inStream.close(); // Close IO stream for memory cost
            outStream.close(); // Close IO stream for memory cost
        } catch ( InvalidKeyException | BadPaddingException |
                NoSuchPaddingException | NoSuchAlgorithmException |
                IllegalBlockSizeException | IOException ex ) {
            throw new Exception("Error during encryption/decryption", ex);
        }
    }

}
