package com.payneteasy.nginxauth.integration;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.StringJoiner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Minimal browser: own cookie jar (the server sets Secure cookies, which java.net.http would not send over
 * plain http), a fixed Host, no redirects followed.
 */
final class Browser {

    private static final Pattern CSRF_INPUT = Pattern.compile("name=\"j_csrf\" value=\"([^\"]+)\"");
    private static final Pattern CSRF_BODY  = Pattern.compile("data-csrf=\"([^\"]+)\"");

    static final class Response {
        final int status;
        final String body;
        final HttpResponse<String> raw;

        Response(HttpResponse<String> aRaw) {
            raw = aRaw;
            status = aRaw.statusCode();
            body = aRaw.body();
        }

        String header(String aName) {
            return raw.headers().firstValue(aName).orElse(null);
        }

        JsonObject json() {
            return JsonParser.parseString(body).getAsJsonObject();
        }

        String csrf() {
            Matcher m = CSRF_INPUT.matcher(body);
            if (m.find()) {
                return m.group(1);
            }
            m = CSRF_BODY.matcher(body);
            return m.find() ? m.group(1) : null;
        }
    }

    final Map<String, String> cookies = new LinkedHashMap<>();
    private final HttpClient client = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();
    private final int port;
    String host = "app1.example.com";
    String origin = "https://app1.example.com";

    Browser(int aPort) {
        port = aPort;
    }

    Response get(String aPath) throws Exception {
        return send(builder(aPath).GET());
    }

    Response get(String aPath, Map<String, String> aHeaders) throws Exception {
        HttpRequest.Builder builder = builder(aPath).GET();
        aHeaders.forEach(builder::header);
        return send(builder);
    }

    Response postForm(String aPath, Map<String, String> aForm) throws Exception {
        return postForm(aPath, aForm, origin);
    }

    Response postForm(String aPath, Map<String, String> aForm, String aOrigin) throws Exception {
        StringJoiner body = new StringJoiner("&");
        aForm.forEach((k, v) -> body.add(URLEncoder.encode(k, StandardCharsets.UTF_8) + "=" + URLEncoder.encode(v, StandardCharsets.UTF_8)));
        HttpRequest.Builder builder = builder(aPath)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body.toString()));
        if (aOrigin != null) {
            builder.header("Origin", aOrigin);
        }
        return send(builder);
    }

    Response postJson(String aPath, JsonObject aBody, String aCsrf) throws Exception {
        HttpRequest.Builder builder = builder(aPath)
                .header("Content-Type", "application/json")
                .header("Origin", origin)
                .POST(HttpRequest.BodyPublishers.ofString(aBody.toString()));
        if (aCsrf != null) {
            builder.header("X-CSRF-Token", aCsrf);
        }
        return send(builder);
    }

    private HttpRequest.Builder builder(String aPath) {
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + aPath)).header("Host", host);
        if (!cookies.isEmpty()) {
            StringJoiner cookie = new StringJoiner("; ");
            cookies.forEach((k, v) -> cookie.add(k + "=" + v));
            builder.header("Cookie", cookie.toString());
        }
        return builder;
    }

    private Response send(HttpRequest.Builder aBuilder) throws Exception {
        HttpResponse<String> response = client.send(aBuilder.build(), HttpResponse.BodyHandlers.ofString());
        for (String setCookie : response.headers().allValues("Set-Cookie")) {
            String pair = setCookie.split(";", 2)[0];
            int eq = pair.indexOf('=');
            String name = pair.substring(0, eq).trim();
            String value = pair.substring(eq + 1).trim();
            if (value.isEmpty() || setCookie.toLowerCase().contains("max-age=0")) {
                cookies.remove(name);
            } else {
                cookies.put(name, value);
            }
        }
        return new Response(response);
    }
}
