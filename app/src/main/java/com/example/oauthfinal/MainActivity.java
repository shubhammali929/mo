package com.example.oauthfinal;

import android.content.Intent;
import android.content.SharedPreferences;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;
import androidx.activity.EdgeToEdge;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;




import org.json.JSONObject;


import com.example.mo.MiniOrangeSSO;

import org.json.JSONException;

import java.security.NoSuchAlgorithmException;

public class MainActivity extends AppCompatActivity {


    MiniOrangeSSO miniOrangeSSO = new MiniOrangeSSO(this);

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        EdgeToEdge.enable(this);
        setContentView(R.layout.activity_main);
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main), (v, insets) -> {
            Insets systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars());
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom);
            return insets;
        });

        miniOrangeSSO.setClientId("VOPiLgXkIeH2gHc");
        miniOrangeSSO.setClientSecret("1TYuX3TQNuHGKeWWaOEufqbJBMs");
        miniOrangeSSO.setBaseUrl("https://testshubham.miniorange.in/");
        miniOrangeSSO.setRedirectUri("https://www.myapplication.com/v1/callback");
        miniOrangeSSO.setPemCertificate("-----BEGIN PUBLIC KEY-----\n" +
                "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzIKQ+V528e3nGaOL72XA\n" +
                "avmL2HAXwdG5+0Cg2X+ezPfSn2U+DxbYOKFyHXfdCj4ocgF1MKk1ECUDhMlZ6vsl\n" +
                "m7ZPuq9Nus6cYeBxSFdKXaC+vI0hpghkGwAl7a6YT4HAbZ3qs+T7My5gaeuXI1j+\n" +
                "8KBOXK8VRDormzQlI0Q+qbfqUSMCNBMsknxFWfgxvvXSBqEOV2Yq0hbp+JSrsB1S\n" +
                "9DefmvNmxUKLDQ65MmInZ7HqfE+ocWt6H0ba9zISCgjSEs4m0fY6fr99EhuQ9vKX\n" +
                "GcxQfvu2qAOHz0te4yQ67xoUGWzMCmZG3TUTfYz+kFVCSJSrmSnTzkppffio7ooA\n" +
                "owIDAQAB\n" +
                "-----END PUBLIC KEY-----\n");

        // Set the listener for login success for grants : oauth code, pkce & implicit````````````````
        miniOrangeSSO.setLoginSuccessListener(new MiniOrangeSSO.LoginSuccessListener() {
            @Override
            public void onLoginSuccess(String userDetails) {
                // Start MainActivity2 with the user details
                Intent intent = new Intent(MainActivity.this, MainActivity2.class);
                intent.putExtra("userDetails", userDetails);
                startActivity(intent);
                finish(); // Close the current activity
            }
            public void onError(String errorMessage) {
                Toast.makeText(MainActivity.this, errorMessage, Toast.LENGTH_LONG).show();
            }
        });

        // Check if SharedPreferences has data ...i.e session is active
        SharedPreferences shrd = getSharedPreferences("userSession", MODE_PRIVATE);
        String firstName = shrd.getString("FirstName", null);
        if (firstName != null) {
            Log.d("mo", "User session retrieved ..");
            Intent intent = new Intent(MainActivity.this, MainActivity2.class);
            startActivity(intent);
            finish(); // Close the current activity
            return;
        }





        Button loginButtonPasswordGrant = findViewById(R.id.button2);
        Button OAuthBtn = findViewById(R.id.oauth);


        // Set up button click listener for Authorization Grant``````````````````
        OAuthBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                miniOrangeSSO.startAuthorizationWithAuthCode();
            }
        });



        // Set up button click listener for Password Grant```````````````````````````
        EditText emailEditText = findViewById(R.id.editTextText5);
        EditText passwordEditText = findViewById(R.id.editTextTextPassword2);
        loginButtonPasswordGrant.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String email = emailEditText.getText().toString();
                String password = passwordEditText.getText().toString();
                miniOrangeSSO.loginWithPasswordGrant(email, password, new MiniOrangeSSO.ResponseCallback() {
                    @Override
                    public void onSuccess(String response) {
                        try {
                            JSONObject jsonObject = new JSONObject(response);
                            String firstName = jsonObject.getString("firstname");
                            String lastName = jsonObject.getString("lastName");
                            Intent intent = new Intent(MainActivity.this, MainActivity2.class);// Redirect to MainActivity2
                            intent.putExtra("userDetails",response);
                            startActivity(intent);
                            finish();
                        } catch (JSONException e) {
                            Toast.makeText(MainActivity.this, "User info parse error", Toast.LENGTH_SHORT).show();
                        }
                    }
                    @Override
                    public void onError(String error) {
                        Toast.makeText(MainActivity.this, error, Toast.LENGTH_SHORT).show();
                    }
                });
            }
        });






        // Set up button click listener for PKCE Grant ```````````````````````
        Button PKCE = findViewById(R.id.pkce);
        PKCE.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                miniOrangeSSO.startAuthorizationWithPKCE();
            }
        });

        // Set up button click for Implicit Grant
        Button ImplicitBtn = findViewById(R.id.implicit);
        ImplicitBtn.setOnClickListener(new View.OnClickListener(){
            @Override
            public void onClick(View v) { miniOrangeSSO.startAuthorizationWithImplicit(); }
        });


        // Check for authorization code in the intent data`````````````````````
        Uri uri = getIntent().getData();
        if(uri != null)
            miniOrangeSSO.handleRedirectUri(uri);




    }
}

