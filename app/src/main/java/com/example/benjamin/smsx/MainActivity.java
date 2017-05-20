package com.example.benjamin.smsx;

import android.Manifest;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.net.Uri;
import android.os.Build;
import android.os.Environment;
import android.support.annotation.RequiresApi;
import android.support.v4.app.ActivityCompat;
import android.support.v4.content.ContextCompat;
import android.support.v4.content.FileProvider;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import org.json.JSONObject;
import org.w3c.dom.Text;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.StringWriter;
import java.net.URI;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.text.DateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import static android.R.attr.data;

public class MainActivity extends AppCompatActivity {

    final private int REQUEST_CODE_ASK_PERMISSIONS = 123;


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);




        final Button button = (Button) findViewById(R.id.button_extract);
        button.setOnClickListener(new View.OnClickListener() {
            @RequiresApi(api = Build.VERSION_CODES.M)
            public void onClick(View v) {
                EditText password = (EditText) findViewById(R.id.editext_password);

                int nSMS = smsx( password.getText().toString() );

                TextView result = (TextView) findViewById(R.id.textView_result);

                String currentDateTimeString = DateFormat.getDateTimeInstance().format(new Date());

                result.setText(currentDateTimeString + "\n" + nSMS + " SMS extracted");

            }
        });

    }


    @RequiresApi(api = Build.VERSION_CODES.M)
    // Returns the number of SMS extracted
    protected int smsx(String password) {
        int hasReadSMS = checkSelfPermission(Manifest.permission.READ_SMS);
        if (hasReadSMS != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[] {Manifest.permission.READ_SMS},
                    REQUEST_CODE_ASK_PERMISSIONS);
            return -1;
        }

        JSONObject allSMS = new JSONObject();


        Uri uri = Uri.parse("content://sms/");
        Cursor c= getContentResolver().query(uri, null, null ,null,null);

        String[] columns =  c.getColumnNames();
        int colIndex = 0;
        int nSMS = c.getCount();

        if(c.moveToFirst()) {
            for(int i=0; i < nSMS; i++) {

                JSONObject tmpSMS = new JSONObject();
                for( String colName : columns) {
                    try {
                        colIndex = c.getColumnIndex( colName );
                        tmpSMS.put( colName, c.getString( colIndex ).toString()  );
                    } catch ( Exception e ) {
                        Log.d("ENTRY", "Error on " + colName);
                    }
                }
                try {
                    allSMS.put( "sms_"+i, tmpSMS );
                } catch ( Exception e ) {
                    Log.d("ENTRY", "JSON error");
                }
                c.moveToNext();
            }
        }
        c.close();


        // Encryption
        byte[] HmacIVEnc = {};
        boolean successfulEncryption = false;
        try {

            HmacIVEnc = encrypt( allSMS.toString(), password );

            successfulEncryption = true;


        } catch ( Exception e ) {
            Log.d("ENCRYPTION", "Encryption error! " + e);
        }


        // Share the data!
        Log.d("SHARE", "Sucessful enc:" + successfulEncryption );
        if( successfulEncryption   ) {
            String fileData =  Base64.encodeToString( HmacIVEnc, Base64.DEFAULT );


            try {

                long timestamp = System.currentTimeMillis() / 1000L;

                File newFile = new File(getFilesDir(), "smsx-" + timestamp + ".txt");
                newFile.createNewFile();

                OutputStream outputStream = new FileOutputStream(newFile);
                outputStream.write( fileData.getBytes() );
                outputStream.close();

                Uri smsURI = FileProvider.getUriForFile(MainActivity.this,
                        BuildConfig.APPLICATION_ID + ".provider",
                        newFile );



                Intent sendIntent = new Intent();
                sendIntent.setAction(Intent.ACTION_SEND);
                sendIntent.putExtra(Intent.EXTRA_STREAM, smsURI );
                sendIntent.setType("text/plain");
                startActivity(sendIntent);
                Log.d("FILE", "done share");

            } catch( Exception e ) {
                Log.e("YOUR_APP_LOG_TAG", "I got an error", e);
            }


            return nSMS;
        }

        return -1;

    }

    // Based on Itaratos code: https://gist.github.com/itarato/abef95871756970a9dad
    // Added salt, increased key length to 256 bit and added HMAC
    public static byte[] encrypt(String plainText, String key) throws Exception {
        byte[] clean = plainText.getBytes();

        // Salting the password doesn't really affect the strength of the AES-key.
        // However, if the attacker knows that the key is SHA256 of a weak password
        // then rainbow table attacks become viable.
        String salt = "SMSX";

        // Generating IV.
        int ivSize = 16;
        byte[] iv = new byte[ivSize];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        // Hashing key.
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update( (key + salt).getBytes("UTF-8") );
        byte[] keyBytes = new byte[32];
        System.arraycopy(digest.digest(), 0, keyBytes, 0, keyBytes.length);
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");

        // Encrypt.
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
        byte[] encrypted = cipher.doFinal(clean);

        // Combine IV and encrypted part.
        byte[] encryptedIVAndText = new byte[ivSize + encrypted.length];
        System.arraycopy(iv,        0, encryptedIVAndText, 0,      ivSize);
        System.arraycopy(encrypted, 0, encryptedIVAndText, ivSize, encrypted.length);

        // Hash the AES key to get a new key.
        MessageDigest signDigest = MessageDigest.getInstance("SHA-256");
        signDigest.update( keyBytes );
        byte[] signKeyBytes = new byte[32];
        System.arraycopy(signDigest.digest(), 0, signKeyBytes, 0, signKeyBytes.length);

        // HMAC(IV+Encrypted)
        SecretKeySpec signingKey = new SecretKeySpec(signKeyBytes, "HmacSHA256");
        Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
        sha256_HMAC.init(signingKey);
        byte[] auth = new byte[32];
        System.arraycopy(sha256_HMAC.doFinal( encryptedIVAndText ), 0, auth, 0, auth.length);

        // Put it all together
        byte[] HmacIVEnc = new byte[encryptedIVAndText.length + auth.length];
        System.arraycopy(auth,               0, HmacIVEnc, 0,           auth.length);
        System.arraycopy(encryptedIVAndText, 0, HmacIVEnc, auth.length, encryptedIVAndText.length);

        //Log.d("noHMAC", "\n" + Base64.encodeToString( encryptedIVAndText, Base64.DEFAULT ) );
        //Log.d("HMAC", "\n" + Base64.encodeToString( HMACencryptedIVAndText, Base64.DEFAULT )  );
        return HmacIVEnc;
    }


}

