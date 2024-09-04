package com.example.mo;
import static android.util.Base64.NO_PADDING;
import static android.util.Base64.NO_WRAP;
import static android.util.Base64.URL_SAFE;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.*;
import java.nio.charset.*;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.Uri;
import android.util.Base64;
import android.util.Log;

import com.android.volley.AuthFailureError;
import com.android.volley.NetworkResponse;
import com.android.volley.Request;
import com.android.volley.RequestQueue;
import com.android.volley.Response;
import com.android.volley.VolleyError;
import com.android.volley.toolbox.JsonObjectRequest;
import com.android.volley.toolbox.StringRequest;
import com.android.volley.toolbox.Volley;

import org.json.JSONException;
import org.json.JSONObject;

import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import java.io.StringReader;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import androidx.annotation.Nullable;


public class MiniOrangeSSO {
    private String clientId;
    private String clientSecret;
    private String baseUrl;
    private String redirectUri;
    private String pemCertificate;
    private Context context;
    private LoginSuccessListener loginSuccessListener;

    public MiniOrangeSSO(Context context) {
        this.context = context;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public void setBaseUrl(String baseUrl) {
        this.baseUrl = baseUrl;
    }

    public void setRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
    }

    public void setPemCertificate(String pemCertificate) {
        this.pemCertificate = pemCertificate;
    }

    String State;


    public void startAuthorizationWithImplicit(){
        Log.d("mo","OAuth initiated using Grant type : Implicit... ");
        SharedPreferences prefs = context.getSharedPreferences("MyApp", Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = prefs.edit();
        editor.putString("grantType", "Implicit");
        editor.apply();
        String state = generateRandomState(20);
        editor.putString("oauth_state", state);
        editor.apply();
        String url = String.format("%s/moas/idp/openidsso?response_type=token&client_id=%s&redirect_uri=%s&scope=openid&state=%s",
                baseUrl, clientId, redirectUri, state);

        Intent intent = new Intent(Intent.ACTION_VIEW, Uri.parse(url));
        context.startActivity(intent);
        Log.d("mo", "User redirected to browser for Implicit Grant.");

    }

    public void startAuthorizationWithPKCE() {
        Log.d("mo","OAuth initiated using Grant type : PKCE... ");
        SharedPreferences prefs = context.getSharedPreferences("MyApp", Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = prefs.edit();
        editor.putString("grantType", "PKCE");
        editor.apply();

        if (clientId == null || baseUrl == null || redirectUri == null) {
            Log.e("MiniOrangeSSO", "SSO configuration is incomplete.");
            return;
        }

        String codeVerifier = generateCodeVerifier();
        String codeChallenge = null;
        try {
            codeChallenge = generateCodeChallenge(codeVerifier);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        State = generateRandomState(20);
        // Save state in SharedPreferences
        editor.putString("oauth_state", State);
        editor.apply();

        // Save codeVerifier in SharedPreferences for later use
        editor.putString("code_verifier", codeVerifier);
        editor.apply();

        String url = String.format("%s/moas/idp/openidsso?client_id=%s&redirect_uri=%s&scope=email openid&response_type=code&code_challenge=%s&code_challenge_method=S256&state=%s",
                baseUrl, clientId, redirectUri, codeChallenge, State);
        Intent intent = new Intent(Intent.ACTION_VIEW, Uri.parse(url));
        context.startActivity(intent);
        Log.d("mo", "User redirected to browser for PKCE authorization.");
    }


    public void startAuthorizationWithAuthCode() {
        Log.d("mo","OAuth initiated using Grant type : Authorisation Code... ");
        SharedPreferences prefs = context.getSharedPreferences("MyApp", Context.MODE_PRIVATE);
        SharedPreferences.Editor editor2 = prefs.edit();
        editor2.putString("grantType", "AUTH_CODE"); // Or any other identifier for normal OAuth
        editor2.apply();


        if (clientId == null || clientSecret == null || baseUrl == null || redirectUri == null) {
            Log.e("MiniOrangeSSO", "SSO configuration is incomplete.");
            return;
        }
        State = generateRandomState(20);
        // Save state in SharedPreferences
        SharedPreferences prefs2 = context.getSharedPreferences("MyApp", Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = prefs2.edit();
        editor.putString("oauth_state", State);
        editor.apply();

        Log.d("mo","State Generated : "+State);
        String url = String.format("%s/moas/idp/openidsso?client_id=%s&redirect_uri=%s&scope=email openid&response_type=code&state=%s", baseUrl, clientId, redirectUri,State);
        Intent intent = new Intent(Intent.ACTION_VIEW, Uri.parse(url));
        context.startActivity(intent);
        Log.d("mo","user redirected to browser..");
    }

    public void handleRedirectUri(Uri uri){
        Log.d("mo", "Control inside handleAuthorizationCode Library class");

        if (uri != null) { // Removed the `startsWith(redirectUri)` check to avoid breaking
            SharedPreferences prefs = context.getSharedPreferences("MyApp", Context.MODE_PRIVATE);
            String grantType = prefs.getString("grantType", null);    //identify grant type from storage
            String savedState = prefs.getString("oauth_state", null); //get state from storage
            String receivedState = uri.getQueryParameter("state");            //get state from uri
            Log.d("mo", "Comparing states...-> " + savedState + " --> " + receivedState);
            if(savedState.equals(receivedState)){
                Log.d("mo","State Verified...");
                if("Implicit".equals(grantType)){ //handling implicit grant
                    String idToken = uri.getQueryParameter("id_token");
                    Log.d("mo","IdToken Received: "+idToken);
                    PublicKey publicKey = null;
                    try {
                        publicKey = JwtUtils.getPublicKeyFromPem(pemCertificate);

                        if (JwtUtils.verifySignature(idToken, publicKey)) {
                            String payload = JwtUtils.decodePayload(idToken);
                            Log.d("mo", "Payload decrypted success : " + payload);
                            // Notify the listener about successful login
                            if (loginSuccessListener != null) {
                                loginSuccessListener.onLoginSuccess(payload);
                            }
                        } else {
                            Log.e("MiniOrangeSSO", "Invalid token signature.");
                        }
                    } catch (Exception e) {
                        Log.e("mo","Exception occured.. :"+e);
                        throw new RuntimeException(e);
                    }
                    Log.d("mo","End of Implicit");
                    return;
                }

                //for Auth code and pkce...
                String code = uri.getQueryParameter("code");

                Log.d("mo", "Auth code received: " + code);
                Log.d("mo", "State Received: " + receivedState);

                String codeVerifier = prefs.getString("code_verifier", null);

                if ("PKCE".equals(grantType)) {
                    // Check if we're using PKCE and the codeVerifier is present
                    if (codeVerifier != null) {
                        requestForToken(code, codeVerifier);
                    } else {
                        Log.e("mo", "PKCE selected but code verifier is missing!");
                    }
                } else {
                    // Regular OAuth flow (Non-PKCE)
                    if (receivedState != null && receivedState.equals(savedState)) {
                        requestForToken(code, null);
                    } else {
                        Log.e("mo", "Invalid State Received or State Mismatch!");
                    }
                }
            }


        } else {
            Log.e("mo", "URI is null. Authorization code not received.");
        }
    }

    public void setLoginSuccessListener(LoginSuccessListener listener) {
        this.loginSuccessListener = listener;
    }


    private void requestForToken(String code, @Nullable String codeVerifier) {
        Log.d("mo", "Auth code received: " + code);
        String postUrl;
        if (codeVerifier != null) {
            Log.d("mo", "PKCE flow: code_verifier found");
            postUrl = String.format("%s/moas/rest/oauth/token?grant_type=authorization_code&client_id=%s&redirect_uri=%s&code=%s&code_verifier=%s",
                    baseUrl, clientId, redirectUri, code, codeVerifier);
        } else {
            Log.d("mo", "Normal OAuth flow: No code_verifier");
            postUrl = String.format("%s/moas/rest/oauth/token?grant_type=authorization_code&client_id=%s&client_secret=%s&redirect_uri=%s&code=%s",
                    baseUrl, clientId, clientSecret, redirectUri, code);
        }

        Log.d("mo", "Making POST request at token endpoint: " + postUrl);

        RequestQueue requestQueue = Volley.newRequestQueue(context);
        JsonObjectRequest jsonObjectRequest = new JsonObjectRequest(Request.Method.POST, postUrl, null,
                response -> {
                    try {
                        String idToken = response.getString("id_token");
                        Log.d("mo", "IdToken Received: " + idToken);

                        PublicKey publicKey = JwtUtils.getPublicKeyFromPem(pemCertificate);
                        if (JwtUtils.verifySignature(idToken, publicKey)) {
                            String payload = JwtUtils.decodePayload(idToken);
                            Log.d("mo", "Payload decrypted successfully: " + payload);

                            if (loginSuccessListener != null) {
                                loginSuccessListener.onLoginSuccess(payload);
                            }
                        } else {
                            Log.e("MiniOrangeSSO", "Invalid token signature.");
                            if (loginSuccessListener != null) {
                                loginSuccessListener.onError("Invalid token signature.");
                            }
                        }
                    } catch (JSONException e) {
                        Log.e("MiniOrangeSSO", "Error extracting id token from response", e);
                        if (loginSuccessListener != null) {
                            loginSuccessListener.onError("Error extracting id token from response.");
                        }
                    } catch (Exception e) {
                        Log.e("MiniOrangeSSO", "Error verifying token", e);
                        if (loginSuccessListener != null) {
                            loginSuccessListener.onError("Error verifying token.");
                        }
                    }
                },
                error -> {
                    Log.e("MiniOrangeSSO", "Error requesting token", error);
                    if (loginSuccessListener != null) {
                        String errorMessage = "Error requesting token";
                        if (error.networkResponse != null) {
                            errorMessage += ": " + error.networkResponse.statusCode;
                        }
                        loginSuccessListener.onError(errorMessage);
                    }
                });

        requestQueue.add(jsonObjectRequest);
    }




    public void loginWithPasswordGrant(String email, String password, ResponseCallback callback) {
        String url = String.format("%s/moas/rest/oauth/token?grant_type=password&client_secret=%s&client_id=%s&username=%s&password=%s",
                baseUrl, clientSecret, clientId, email, password);
        Log.d("mo", "Making POST request to token endpoint URL: " + url);

        RequestQueue requestQueue = Volley.newRequestQueue(context);

        JsonObjectRequest jsonObjectRequest = new JsonObjectRequest(Request.Method.POST, url, null,
                response -> {
                    try {
                        String accessToken = response.getString("access_token");
                        Log.d("mo", "Access token received: " + accessToken);

                        // Fetch user info after obtaining access token
                        Log.d("mo","Fetching user info after obtaining access token...");
                        fetchUserInfo(accessToken, callback);
                    } catch (JSONException e) {
                        Log.e("MiniOrangeSSO", "Error parsing access token", e);
                        callback.onError("Error parsing access token");
                    }
                },
                error -> {
                    Log.e("MiniOrangeSSO", "Error in loginWithPasswordGrant", error);
                    callback.onError("Login error: " + error.toString());
                });

        requestQueue.add(jsonObjectRequest);

//         Alternative way--------------↘️
//        JsonObjectRequest jsonObjectRequest = new JsonObjectRequest(Request.Method.POST, url, null,
//                new Response.Listener<JSONObject>() {
//                    @Override
//                    public void onResponse(JSONObject response) {
//                        try {
//                            String accessToken = response.getString("access_token");
//                            Log.d("mo", "Access token received: " + accessToken);
//
//                            // Fetch user info after obtaining access token
//                            fetchUserInfo(accessToken, callback);
//                        } catch (JSONException e) {
//                            Log.e("MiniOrangeSSO", "Error parsing access token", e);
//                            callback.onError("Error parsing access token");
//                        }
//                    }
//                },
//                new Response.ErrorListener() {
//                    @Override
//                    public void onErrorResponse(VolleyError error) {
//                        Log.e("MiniOrangeSSO", "Error in loginWithPasswordGrant", error);
//                        callback.onError("Login error: " + error.toString());
//                    }
//                });
//
//        requestQueue.add(jsonObjectRequest);
    }

    public void fetchUserInfo(String accessToken, ResponseCallback callback) {
        Log.d("mo","control inside fetchUserInfo function...");
        String url = String.format("%s/moas/rest/oauth/getuserinfo", baseUrl);
        Log.d("mo", "Fetching user info with access token: " + accessToken);

        RequestQueue requestQueue = Volley.newRequestQueue(context);

        JsonObjectRequest jsonObjectRequest = new JsonObjectRequest(Request.Method.GET, url, null,
                response -> {
                    Log.d("mo", "User info fetched: " + response.toString());
                    callback.onSuccess(response.toString());
                },
                error -> {
                    Log.e("MiniOrangeSSO", "Error in fetchUserInfo", error);
                    // Log detailed error response for debugging
                    NetworkResponse networkResponse = error.networkResponse;
                    if (networkResponse != null) {
                        String statusCode = String.valueOf(networkResponse.statusCode);
                        String errorData = new String(networkResponse.data);
                        Log.e("MiniOrangeSSO", "Server error response: " + statusCode + " " + errorData);
                        callback.onError("User info fetch error: " + statusCode + " " + errorData);
                    } else {
                        callback.onError("User info fetch error: " + error.toString());
                    }
                }) {
            @Override
            public Map<String, String> getHeaders() {
                Map<String, String> headers = new HashMap<>();
                headers.put("Authorization", "Bearer " + accessToken);
                return headers;
            }
        };
        requestQueue.add(jsonObjectRequest);
    }


    public interface LoginSuccessListener {
        void onLoginSuccess(String userDetails);
        void onError(String errorMessage);
    }

    public interface ResponseCallback {
        void onSuccess(String response);
        void onError(String error);
    }


    public static String generateRandomState(int n)
    {
        String candidateChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
        int length = 15;
        StringBuilder sb = new StringBuilder ();
        Random random = new Random ();
        for (int i = 0; i < length; i ++) {
            sb.append (candidateChars.charAt (random.nextInt (candidateChars
                    .length ())));
        }

        return sb.toString ();
    }

    public String generateCodeVerifier() {
        SecureRandom sr = new SecureRandom();
        byte[] code = new byte[32];
        sr.nextBytes(code);

        String codeVerifier = Base64.encodeToString(code, URL_SAFE | NO_WRAP | NO_PADDING);
        Log.d("mo", "CodeVerifier: " + codeVerifier);
        return codeVerifier;
    }

    public String generateCodeChallenge(String codeVerifier) throws NoSuchAlgorithmException {
        byte[] bytes = codeVerifier.getBytes(StandardCharsets.US_ASCII);
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(bytes, 0, bytes.length);
        byte[] digest = md.digest();
        String codeChallenge = Base64.encodeToString(digest, URL_SAFE | NO_PADDING | NO_WRAP);
        Log.d("mo", "CodeChallenge: " + codeChallenge);
        return codeChallenge;
    }

}
class JwtUtils {

    static {
        // Add the BouncyCastle Provider once during class loading
        Security.addProvider(new BouncyCastleProvider());
    }

    // Split JWT into its three parts
    public static String[] splitToken(String jwt) throws IllegalArgumentException {
        String[] parts = jwt.split("\\.");
        if (parts.length != 3) {
            throw new IllegalArgumentException("Invalid JWT token format.");
        }
        return parts;
    }

    // Load PEM public key and get PublicKey object
    public static PublicKey getPublicKeyFromPem(String pem) throws Exception {
        if (pem == null || pem.isEmpty()) {
            throw new IllegalArgumentException("PEM string cannot be null or empty.");
        }

        try (PemReader pemReader = new PemReader(new StringReader(pem))) {
            PemObject pemObject = pemReader.readPemObject();
            if (pemObject == null) {
                throw new IllegalArgumentException("Invalid PEM format: Could not read PEM object.");
            }
            byte[] content = pemObject.getContent();

            X509EncodedKeySpec spec = new X509EncodedKeySpec(content);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(spec);
        } catch (Exception e) {
            throw new Exception("Failed to parse PEM public key", e);

        }
    }

    // Verify JWT signature
    public static boolean verifySignature(String jwt, PublicKey publicKey) throws Exception {
        String[] parts = splitToken(jwt);
        String headerAndPayload = parts[0] + "." + parts[1];
        byte[] signature = decodeBase64Url(parts[2]);

        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(publicKey);
        sig.update(headerAndPayload.getBytes());
        return sig.verify(signature);
    }

    // Decode JWT payload
    public static String decodePayload(String jwt) {
        String[] splitToken = jwt.split("\\.");
        if (splitToken.length < 2) {
            throw new IllegalArgumentException("Invalid JWT token format.");
        }
        return new String(Base64.decode(splitToken[1], Base64.URL_SAFE));
    }

    // Decode Base64 URL-safe string
    public static byte[] decodeBase64Url(String base64Url) {
        return Base64.decode(base64Url, Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP);
    }
}


