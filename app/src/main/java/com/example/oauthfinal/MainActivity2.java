package com.example.oauthfinal;

import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.util.Log;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import org.json.JSONException;
import org.json.JSONObject;

public class MainActivity2 extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main2);
        Log.d("myapp", "MainActivity2 Started");

        //retrive username from sharedPreferences
        SharedPreferences shrd = getSharedPreferences("userSession", MODE_PRIVATE);
        String firstName = shrd.getString("FirstName", "USER NULL");


        if (!"USER NULL".equals(firstName)) { //if user is already logged in then set username from sharedPreferences
            TextView textView = findViewById(R.id.username);
            textView.setText(firstName);
        } else { //if user has made fresh login then ...
            // Retrieve the user details from the Intent(MainActivity1) if present
            String userDetails = getIntent().getStringExtra("userDetails");

            if (userDetails != null) {
                try {
                    JSONObject jsonObject = new JSONObject(userDetails);
                    String fullName = jsonObject.getString("Attr1_fullname");
                    String email = jsonObject.getString("Attr2_email");
                    // Log and show the user's first name
                    Log.d("myapp", "Welcome " + fullName);

                    // Store user details in SharedPreferences
                    SharedPreferences.Editor editor = shrd.edit();
                    editor.putString("FirstName", fullName);
                    editor.apply();

                    // Update the TextView with the new first name
                    TextView textView = findViewById(R.id.username);
                    textView.setText(fullName);

                } catch (JSONException e) {
                    e.printStackTrace();
                    Toast.makeText(MainActivity2.this, "Error parsing user details: " + e.getMessage(), Toast.LENGTH_LONG).show();
                    Log.e("myapp", "Error parsing user details ");
                }
            } else {
                Log.e("myapp", "userDetails is null");
                Toast.makeText(MainActivity2.this, "Error: userDetails is null", Toast.LENGTH_LONG).show();

            }
        }

        // Logout button functionality
        Button logoutButton = findViewById(R.id.logout);
        logoutButton.setOnClickListener(v -> {
            // Clear all SharedPreferences
            SharedPreferences.Editor editor = shrd.edit();
            editor.clear();
            editor.apply();
            Log.d("myapp", "User Logged out sucessfully ...");

            // Redirect to Login Activity
            Intent intent = new Intent(MainActivity2.this, MainActivity.class);
            intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK); // Clear back stack
            startActivity(intent);
            Log.d("myapp", "Redirected to login page..");
            finish(); // Close the current activity
        });
    }
}
