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
        miniOrangeSSO.setpemCertificate("-----BEGIN PUBLIC KEY-----\n" +
                "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzIKQ+V528e3nGaOL72XA\n" +
                "avmL2HAXwdG5+0Cg2X+ezPfSn2U+DxbYOKFyHXfdCj4ocgF1MKk1ECUDhMlZ6vsl\n" +
                "m7ZPuq9Nus6cYeBxSFdKXaC+vI0hpghkGwAl7a6YT4HAbZ3qs+T7My5gaeuXI1j+\n" +
                "8KBOXK8VRDormzQlI0Q+qbfqUSMCNBMsknxFWfgxvvXSBqEOV2Yq0hbp+JSrsB1S\n" +
                "9DefmvNmxUKLDQ65MmInZ7HqfE+ocWt6H0ba9zISCgjSEs4m0fY6fr99EhuQ9vKX\n" +
                "GcxQfvu2qAOHz0te4yQ67xoUGWzMCmZG3TUTfYz+kFVCSJSrmSnTzkppffio7ooA\n" +
                "owIDAQAB\n" +
                "-----END PUBLIC KEY-----\n");

        // Set the listener for login success````````````````
        miniOrangeSSO.setLoginSuccessListener(new MiniOrangeSSO.LoginSuccessListener() {
            @Override
            public void onLoginSuccess(String userDetails) {
                // Start MainActivity2 with the user details
                Intent intent = new Intent(MainActivity.this, MainActivity2.class);
                Log.d("myapp", "onLoginSuccess: "+userDetails);
                intent.putExtra("userDetails", userDetails);
                startActivity(intent);
                Log.d("myapp", "Redirected user to second activity ..");
                finish(); // Close the current activity
            }
        });

        // Check if SharedPreferences has data
        SharedPreferences shrd = getSharedPreferences("userSession", MODE_PRIVATE);
        String firstName = shrd.getString("FirstName", null);
        if (firstName != null) {
            Log.d("myapp", "User session retrieved ..");
            Intent intent = new Intent(MainActivity.this, MainActivity2.class);
            startActivity(intent);
            finish(); // Close the current activity
            return;
        }

        // Check for authorization code in the intent data`````````````````````
        Uri uri = getIntent().getData();
        miniOrangeSSO.handleAuthorizationCode(uri);

        EditText emailEditText = findViewById(R.id.editTextText5);
        EditText passwordEditText = findViewById(R.id.editTextTextPassword2);
        Button loginButtonPasswordGrant = findViewById(R.id.button2);
        Button OAuthBtn = findViewById(R.id.oauth);

        // Set up button click listener for Authorization Grant``````````````````
        OAuthBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                miniOrangeSSO.startAuthorization();
            }
        });

        // Set up button click listener for Password Grant
        loginButtonPasswordGrant.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String email = emailEditText.getText().toString();
                String password = passwordEditText.getText().toString();
                miniOrangeSSO.loginWithPasswordGrant(email, password, new MiniOrangeSSO.ResponseCallback() {
                    @Override
                    public void onSuccess(String response) {
                        miniOrangeSSO.fetchUserInfo(response, new MiniOrangeSSO.ResponseCallback() {
                            @Override
                            public void onSuccess(String response) {
                                // Parse and save user info
                                try {
                                    JSONObject jsonObject = new JSONObject(response);
                                    String firstName = jsonObject.getString("firstname");
                                    String lastName = jsonObject.getString("lastname");
                                    String userName = jsonObject.getString("username");

                                    SharedPreferences sharedPreferences = getSharedPreferences("userSession", MODE_PRIVATE);
                                    SharedPreferences.Editor editor = sharedPreferences.edit();
                                    editor.putString("FirstName", firstName);
                                    editor.putString("LastName", lastName);
                                    editor.putString("UserName", userName);
                                    editor.apply();

                                    // Redirect to MainActivity2
                                    Intent intent = new Intent(MainActivity.this, MainActivity2.class);
                                    startActivity(intent);
                                    finish();

                                } catch (JSONException e) {
                                    Log.e("MainActivity", "Error parsing user info JSON", e);
                                }
                            }

                            @Override
                            public void onError(String error) {
                                Toast.makeText(MainActivity.this, "User info fetch error: " + error, Toast.LENGTH_SHORT).show();
                            }
                        });
                    }
                    @Override
                    public void onError(String error) {
                        Toast.makeText(MainActivity.this, "Login error: " + error, Toast.LENGTH_SHORT).show();
                    }
                });
            }
        });
    }
}

