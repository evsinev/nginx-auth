package com.payneteasy.nginxauth.servlet.api;

import com.google.gson.Gson;
import com.payneteasy.nginxauth.service.IAuthService;
import com.payneteasy.nginxauth.service.UserMustChangePasswordException;
import com.payneteasy.nginxauth.service.impl.RateLimiter;
import com.payneteasy.nginxauth.servlet.api.messages.CheckUsernamePasswordRequest;
import com.payneteasy.nginxauth.util.HttpRequestUtil;

import javax.naming.AuthenticationException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;
import java.util.Set;

import static com.payneteasy.nginxauth.util.StringUtils.isEmpty;

public class ApiCheckUsernamePasswordServlet extends HttpServlet {

    private final IAuthService authService;
    private final Gson         gson;
    private final Set<String>  accessTokens;

    public ApiCheckUsernamePasswordServlet(IAuthService authService, Gson gson, Set<String> accessTokens) {
        this.authService  = authService;
        this.gson         = gson;
        this.accessTokens = accessTokens;
    }

    @Override
    protected void doPost(HttpServletRequest aRequest, HttpServletResponse aResponse) throws IOException {
        ApiContext api = new ApiContext(aRequest, aResponse, gson, accessTokens);

        Optional<String> errorOpt = api.checkAccessToken();
        if (errorOpt.isPresent()) {
            api.writeError(401, errorOpt.get());
            return;
        }

        CheckUsernamePasswordRequest checkRequest = api.fromJson(CheckUsernamePasswordRequest.class);

        if (isEmpty(checkRequest.getUsername())) {
            api.writeError(400, "Field username is empty");
            return;
        }

        if (isEmpty(checkRequest.getPassword())) {
            api.writeError(400, "Field password is empty");
            return;
        }

        String username = checkRequest.getUsername();
        String ip = HttpRequestUtil.clientIp(aRequest);
        RateLimiter rateLimiter = RateLimiter.getInstance();
        if (rateLimiter.isBlocked(RateLimiter.userKey(username))
                || rateLimiter.isBlocked(RateLimiter.ipKey(ip))) {
            api.writeError(401, "Authentication failed");
            return;
        }

        try {
            authService.authenticate(username, checkRequest.getPassword(), true);
            rateLimiter.recordSuccess(RateLimiter.userKey(username));
            api.writeSuccessResponse(username);
        } catch (AuthenticationException e) {
            rateLimiter.recordFailure(RateLimiter.userKey(username));
            rateLimiter.recordFailure(RateLimiter.ipKey(ip));
            api.writeError(401, "Authentication failed", e);
        } catch (UserMustChangePasswordException e) {
            api.writeError(403, "User must change password", e);
        }
    }
}
