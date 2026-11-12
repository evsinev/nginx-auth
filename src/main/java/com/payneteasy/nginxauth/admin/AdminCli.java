package com.payneteasy.nginxauth.admin;

import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.payneteasy.nginxauth.util.SettingsManager;

import java.io.PrintStream;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

/**
 * {@code java -jar nginx-auth.jar admin <command>}: talks to the running service on 127.0.0.1:WEBAUTHN_ADMIN_PORT.
 */
public final class AdminCli {

    private static final String USAGE = String.join("\n",
            "Usage: java -jar nginx-auth.jar admin <command> <uid> [options]",
            "",
            "Commands:",
            "  reset <uid> [--grant] [--ttl-hours N] [--uses N] [--by NAME]",
            "        delete all security keys of the user, end sessions; with --grant issue an enrollment secret",
            "  grant <uid> [--ttl-hours N] [--uses N] [--by NAME]",
            "        issue an enrollment secret (replaces an existing one)",
            "  show <uid>",
            "        list security keys and the enrollment grant",
            "",
            "Environment: WEBAUTHN_ADMIN_TOKEN (required), WEBAUTHN_ADMIN_PORT (default 9092)");

    private AdminCli() {
    }

    public static void main(String[] aArgs) {
        System.exit(run(aArgs, System.out, System.err));
    }

    static int run(String[] aArgs, PrintStream aOut, PrintStream aErr) {
        if (aArgs.length < 2) {
            aErr.println(USAGE);
            return 2;
        }
        String command = aArgs[0];
        String uid = aArgs[1];
        boolean grant = false;
        Long ttlHours = null;
        Long uses = null;
        String by = System.getProperty("user.name");
        try {
            for (int i = 2; i < aArgs.length; i++) {
                switch (aArgs[i]) {
                    case "--grant" -> grant = true;
                    case "--ttl-hours" -> ttlHours = Long.parseLong(aArgs[++i]);
                    case "--uses" -> uses = Long.parseLong(aArgs[++i]);
                    case "--by" -> by = aArgs[++i];
                    default -> throw new IllegalArgumentException("Unknown option " + aArgs[i]);
                }
            }
        } catch (RuntimeException e) {
            aErr.println(e.getMessage() == null ? USAGE : e.getMessage());
            return 2;
        }

        String token = SettingsManager.getWebAuthnAdminToken();
        if (token == null || token.isBlank()) {
            aErr.println("WEBAUTHN_ADMIN_TOKEN is not set");
            return 2;
        }
        String base = "http://127.0.0.1:" + SettingsManager.getWebAuthnAdminPort().trim() + "/admin/webauthn";

        JsonObject body = new JsonObject();
        body.addProperty("uid", uid);
        body.addProperty("issuedBy", by);
        if (ttlHours != null) {
            body.addProperty("ttlHours", ttlHours);
        }
        if (uses != null) {
            body.addProperty("uses", uses);
        }
        HttpRequest.Builder request;
        switch (command) {
            case "reset" -> {
                body.addProperty("grant", grant);
                request = post(base + "/reset", body);
            }
            case "grant" -> request = post(base + "/grant", body);
            case "show" -> request = HttpRequest.newBuilder(URI.create(base + "/user?uid=" + URLEncoder.encode(uid, StandardCharsets.UTF_8))).GET();
            default -> {
                aErr.println(USAGE);
                return 2;
            }
        }
        try {
            HttpResponse<String> response = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build()
                    .send(request.header("Authorization", "Bearer " + token.trim()).timeout(Duration.ofSeconds(30)).build(),
                            HttpResponse.BodyHandlers.ofString());
            JsonObject result = JsonParser.parseString(response.body()).getAsJsonObject();
            if (response.statusCode() != 200) {
                aErr.println("Error: " + (result.has("error") ? result.get("error").getAsString() : response.statusCode()));
                return 1;
            }
            if (result.has("secret")) {
                String secret = result.remove("secret").getAsString();
                aOut.println("Enrollment secret (shown once, give it to the user over a trusted channel):");
                aOut.println();
                aOut.println("    " + secret);
                aOut.println();
            }
            aOut.println(new GsonBuilder().setPrettyPrinting().create().toJson(result));
            return 0;
        } catch (Exception e) {
            aErr.println("Can't reach nginx-auth admin API at " + base + ": " + e.getMessage());
            return 1;
        }
    }

    private static HttpRequest.Builder post(String aUrl, JsonObject aBody) {
        return HttpRequest.newBuilder(URI.create(aUrl))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(aBody.toString()));
    }
}
