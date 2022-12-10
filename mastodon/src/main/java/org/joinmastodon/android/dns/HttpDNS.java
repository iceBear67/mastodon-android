package org.joinmastodon.android.dns;

import android.util.Log;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import okhttp3.Dns;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

public class HttpDNS implements Dns {
    private static final OkHttpClient CLIENT = new OkHttpClient.Builder().build();
    public static final HttpDNS CLOUDFLARE = new HttpDNS("https://1.1.1.1/dns-query?name=");
    public static final HttpDNS DNSSB = new HttpDNS("https://45.11.45.11/dns-query?name=");
    private Map<String, Long> TTL = new HashMap<>();
    private Map<String, List<InetAddress>> cache = new HashMap<>();
    private final String apiPrefix;

    public HttpDNS(String api) {
        this.apiPrefix = api;
    }

    @Override
    public List<InetAddress> lookup(String s) throws UnknownHostException {
        if (TTL.containsKey(s)) {
            if (TTL.get(s) > System.currentTimeMillis()) {
                return cache.get(s);
            }
        }
        Request req = new Request.Builder()
                .addHeader("accept", "application/dns-json")
                .url(apiPrefix + s + "&type=A")
                .build();
        Log.d("HttpDNS", req.url().toString());
        try {
            Response response = CLIENT.newCall(req).execute();
            if (response.code() != 200) {
                return Dns.SYSTEM.lookup(s);
            }
            JsonElement resp = JsonParser.parseString(response.body().string());
            List<InetAddress> addresses = new ArrayList<>();
            JsonArray answers = resp.getAsJsonObject().getAsJsonArray("Answer");
            if (answers == null || answers.isEmpty()) {
                return Dns.SYSTEM.lookup(s);
            }
            Iterator<JsonElement> joIt = answers.iterator();
            while (joIt.hasNext()) {
                JsonObject jo = joIt.next().getAsJsonObject();
                int ttl = jo.get("TTL").getAsInt();
                String result = jo.get("data").getAsString();
                if (result.length() > 3 * 4 + 3) continue;
                TTL.put(result, System.currentTimeMillis() + ttl * 1000);
                try {
                    addresses.add(InetAddress.getByName(result));
                    Log.d("HttpDNS","Resolved! "+result);
                } catch (Exception exc) {
                    Log.e("HttpDNS", "Unexcepted error at InetAddress creation, result: " + result, exc);
                }
            }
            cache.put(s, addresses);
            return addresses;
        } catch (IOException e) {
            Log.e("HttpDNS", "Cannot connect to " + req.url(), e);
        }
        return Dns.SYSTEM.lookup(s);
    }
}
