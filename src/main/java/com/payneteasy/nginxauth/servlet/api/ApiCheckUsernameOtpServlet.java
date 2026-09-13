package com.payneteasy.nginxauth.servlet.api;

import com.google.gson.Gson;
import com.payneteasy.nginxauth.service.IOneTimePasswordService;
import com.payneteasy.nginxauth.service.impl.RateLimiter;
import com.payneteasy.nginxauth.servlet.api.messages.CheckUsernameOtpRequest;
import com.payneteasy.nginxauth.util.LoginAttempts;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;
import java.util.Set;

import static com.payneteasy.nginxauth.util.StringUtils.isEmpty;

public class ApiCheckUsernameOtpServlet extends HttpServlet {

    private final IOneTimePasswordService oneTimePasswordService;
    private final Gson                    gson;
    private final Set<String>             accessTokens;

    public ApiCheckUsernameOtpServlet(IOneTimePasswordService oneTimePasswordService, Gson gson, Set<String> accessTokens) {
        this.oneTimePasswordService = oneTimePasswordService;
        this.gson                   = gson;
        this.accessTokens           = accessTokens;
    }

    @Override
    protected void doPost(HttpServletRequest aRequest, HttpServletResponse aResponse) throws IOException {
        ApiContext api = new ApiContext(aRequest, aResponse, gson, accessTokens);

        Optional<String> errorOpt = api.checkAccessToken();
        if (errorOpt.isPresent()) {
            api.writeError(401, errorOpt.get());
            return;
        }

        CheckUsernameOtpRequest checkRequest = api.fromJson(CheckUsernameOtpRequest.class);

        if (isEmpty(checkRequest.getUsername())) {
            api.writeError(400, "Field username is empty");
            return;
        }

        if (isEmpty(checkRequest.getOtp())) {
            api.writeError(400, "Field otp is empty");
            return;
        }

        long otp;
        try {
            otp = Long.parseLong(checkRequest.getOtp());
        } catch (NumberFormatException e) {
            api.writeError(400, "OTP code is not a number");
            return;
        }

        String username = checkRequest.getUsername();
        RateLimiter.Attempt attempt = LoginAttempts.begin(aRequest, username);
        attempt.awaitDelay();
        if (attempt.denied()) {
            api.writeError(429, "Too many attempts");
            return;
        }

        if (!oneTimePasswordService.checkCode(username, otp)) {
            attempt.failed();
            api.writeError(401, "Bad OTP code");
            return;
        }

        attempt.succeeded();
        api.writeSuccessResponse(username);
    }
}
