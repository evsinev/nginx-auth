package com.payneteasy.nginxauth.servlet.api;

import com.google.gson.Gson;
import com.payneteasy.nginxauth.servlet.api.messages.CheckAuthResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static com.payneteasy.nginxauth.util.StringUtils.isEmpty;

public class ApiContext {

    private static final Logger LOG = LoggerFactory.getLogger( ApiContext.class );

    private final HttpServletRequest  httpRequest;
    private final HttpServletResponse httpResponse;
    private final Gson                gson;
    private final Set<String>         accessTokens;

    public ApiContext(HttpServletRequest httpRequest, HttpServletResponse httpResponse, Gson gson, Set<String> accessTokens) {
        this.httpRequest  = httpRequest;
        this.httpResponse = httpResponse;
        this.gson         = gson;
        this.accessTokens = accessTokens;
    }

    public <T> T fromJson(Class<T> clazz) throws IOException {
        return gson.fromJson(httpRequest.getReader(), clazz);
    }

    public void writeError(int aStatus, String aError) throws IOException {
        writeError(aStatus, aError, null);
    }

    public void writeError(int aStatus, String aError, Exception e) throws IOException {
        httpResponse.setStatus(aStatus);
        httpResponse.setContentType("application/json");
        httpResponse.setCharacterEncoding("UTF-8");

        CheckAuthResponse checkResponse = CheckAuthResponse.builder()
                .success      ( false    )
                .errorMessage ( aError   )
                .status       ( aStatus  )
                .errorId      (UUID.randomUUID().toString() )
                .build();

        String json = gson.toJson(checkResponse);
        LOG.error("Error is {}", json, e);

        httpResponse.getWriter().write(json);
    }

    public Optional<String> checkAccessToken() {
        String token = httpRequest.getHeader("Authorization");
        if (isEmpty(token)) {
            return Optional.of("No Authorization header found");
        }

        if (accessTokens.contains(token)) {
            return Optional.empty();
        }

        return Optional.of("Bad access token");
    }

    public void writeSuccessResponse(String aUsername) throws IOException {
        LOG.info("Successfully authenticated user {}", aUsername);

        CheckAuthResponse response = CheckAuthResponse.builder()
                .success ( true )
                .build();

        httpResponse.setStatus(200);
        httpResponse.setContentType("application/json");
        httpResponse.setCharacterEncoding("UTF-8");

        gson.toJson(response, httpResponse.getWriter());
    }
}
