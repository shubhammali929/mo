package com.example.mo;

import android.content.Context;
import android.content.Intent;
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

    public void setpemCertificate(String pemCertificate) {
        this.pemCertificate = pemCertificate;
    }

    public void startAuthorization() {
        if (clientId == null || clientSecret == null || baseUrl == null || redirectUri == null) {
            Log.e("MiniOrangeSSO", "SSO configuration is incomplete.");
            return;
        }

        String url = String.format("%s/moas/idp/openidsso?client_id=%s&redirect_uri=%s&scope=email openid&response_type=code&state=abcd", baseUrl, clientId, redirectUri);
        Intent intent = new Intent(Intent.ACTION_VIEW, Uri.parse(url));
        context.startActivity(intent);
        Log.d("MiniOrangeSSO", "OAuth initiated ...");
    }

    public void handleAuthorizationCode(Uri uri) {
        Log.d("myapp","inside handleAuthorizationCode");
        if (uri != null ) { //code gets break at --> && uri.toString().startsWith(redirectUri)
            String code = uri.getQueryParameter("code");
            String state = uri.getQueryParameter("state");
            Log.d("MiniOrangeSSO", "Auth code received: " + code);
            requestForToken(code);
        }
    }
    public void setLoginSuccessListener(LoginSuccessListener listener) {
        this.loginSuccessListener = listener;
    }

    private void requestForToken(String code) {
        String postUrl = String.format("%s/moas/rest/oauth/token?grant_type=authorization_code&client_id=%s&client_secret=%s&redirect_uri=%s&code=%s",
                baseUrl, clientId, clientSecret, redirectUri, code);

        Log.d("MiniOrangeSSO", "Making call on token endpoint with post URL: " + postUrl);

        RequestQueue requestQueue = Volley.newRequestQueue(context);
        JsonObjectRequest jsonObjectRequest = new JsonObjectRequest(Request.Method.POST, postUrl, null,
                new Response.Listener<JSONObject>() {
                    @Override
                    public void onResponse(JSONObject response) {
                        Log.d("MiniOrangeSSO", "Response received: " + response.toString());
                        try {
                            String idToken = response.getString("id_token");
                            // Process the token, e.g., verify it, decode payload, etc.

                            try {
                                PublicKey publicKey = JwtUtils.getPublicKeyFromPem(pemCertificate);
                                if (JwtUtils.verifySignature(idToken, publicKey)) {
                                    String payload = JwtUtils.decodePayload(idToken);
                                    Log.d("myapp", "Payload decrypted success: " + payload);

                                    // Notify the listener about successful login
                                    if (loginSuccessListener != null) {
                                        loginSuccessListener.onLoginSuccess(payload);
                                    }
                                } else {
                                    Log.e("myapp","invalid token error");
                                }
                            } catch (Exception e) {
                                e.printStackTrace();
                                Log.e("myapp","error occurred "+e);
                            }
                        } catch (JSONException e) {
                            Log.e("MiniOrangeSSO", "Error extracting id token from response", e);
                        }
                    }
                },
                new Response.ErrorListener() {
                    @Override
                    public void onErrorResponse(VolleyError error) {
                        NetworkResponse networkResponse = error.networkResponse;
                        if (networkResponse != null) {
                            Log.e("MiniOrangeSSO", "Error response code: " + networkResponse.statusCode);
                        }
                    }
                }
        );
        requestQueue.add(jsonObjectRequest);
    }

    public void loginWithPasswordGrant(String email, String password, ResponseCallback callback) {
        String url = String.format("%s/moas/rest/oauth/token?grant_type=password&client_secret=%s&client_id=%s&username=%s&password=%s",
                baseUrl, clientSecret, clientId, email, password);
        Log.d("MiniOrangeSSO", "Making POST request to token endpoint URL: " + url);

        RequestQueue requestQueue = Volley.newRequestQueue(context);
        JsonObjectRequest jsonObjectRequest = new JsonObjectRequest(Request.Method.POST, url, null,
                new Response.Listener<JSONObject>() {
                    @Override
                    public void onResponse(JSONObject response) {
                        try {
                            String accessToken = response.getString("access_token");
                            callback.onSuccess(accessToken);
                            Log.d("MiniOrangeSSO", "Access token received: " + accessToken);
                        } catch (JSONException e) {
                            callback.onError("JSON parsing error: " + e.getMessage());
                        }
                    }
                },
                new Response.ErrorListener() {
                    @Override
                    public void onErrorResponse(VolleyError error) {
                        callback.onError("Request error: " + error.getMessage());
                    }
                }
        );
        requestQueue.add(jsonObjectRequest);
    }

    public void fetchUserInfo(String token, ResponseCallback callback) {
        String userInfoUrl = String.format("%s/moas/rest/oauth/getuserinfo", baseUrl);
        Log.d("MiniOrangeSSO", "Making GET request to getuserinfo endpoint: " + userInfoUrl);

        RequestQueue requestQueue = Volley.newRequestQueue(context);
        StringRequest stringRequest = new StringRequest(Request.Method.GET, userInfoUrl,
                new Response.Listener<String>() {
                    @Override
                    public void onResponse(String response) {
                        callback.onSuccess(response);
                    }
                },
                new Response.ErrorListener() {
                    @Override
                    public void onErrorResponse(VolleyError error) {
                        callback.onError("Request error: " + error.getMessage());
                    }
                }) {
            @Override
            public Map<String, String> getHeaders() throws AuthFailureError {
                Map<String, String> headers = new HashMap<>();
                headers.put("Authorization", "Bearer " + token);
                return headers;
            }
        };

        requestQueue.add(stringRequest);
    }
    public interface LoginSuccessListener {
        void onLoginSuccess(String userDetails);
    }
    public interface ResponseCallback {
        void onSuccess(String response);
        void onError(String error);
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


